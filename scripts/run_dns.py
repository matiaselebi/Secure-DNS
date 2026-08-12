#!/usr/bin/env python3
"""Punto de entrada de SecureDNS. Levanta dos cosas distintas según el modo.

EN MODO PROPIO (como funcionó siempre)
    el resolutor en el puerto 53 más el panel.

EN MODO PI-HOLE (la jubilación del resolutor)
    NO se abre el 53 y NO se toca el DNS del sistema. Se levanta el panel, se
    le publican las listas a Pi-hole cada tantas horas, y se le importan las
    consultas cada pocos minutos para correrles encima la detección de
    túneles, las categorías, los hallazgos normales y el puntaje.

Quién resuelve lo decide `src/securedns/modo.py`, en un solo lugar. Ver el
comentario de `dns.modo` en el config.yaml.
"""

import os
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

PID_FILE = PROJECT_ROOT / "data" / "dns.pid"

# Misma idea que en SecureProxy: releer blocklist/allowlist desde disco cada
# pocos segundos (liviano, son archivos de texto chicos), separado del ciclo
# pesado de descarga de feeds (horas). Así un dominio agregado a mano
# (editando el .txt, desde el menú .bat, o por otro medio que no sea el
# propio dashboard) se aplica solo, sin reiniciar el proceso.
LIGHT_RELOAD_INTERVAL_SECONDS = 15

import update_blocklist  # noqa: E402
from securedns.blocklist import Allowlist, Blocklist  # noqa: E402
from securedns.config_loader import load_config  # noqa: E402
from securedns.dashboard import build_dashboard_server  # noqa: E402
from securedns.dns_server import ThreatIntelResolver, build_dns_server  # noqa: E402
from securedns.alertas import MotorDeAlertas  # noqa: E402
from securedns.desktop_alerts import DesktopNotifier  # noqa: E402
from securedns.geoip import GeoIP  # noqa: E402
from securedns.notifier import TelegramNotifier  # noqa: E402
from securedns.logger_db import LoggerDB  # noqa: E402
from securedns.rdap import ClienteRDAP  # noqa: E402
from securedns import modo as modo_dns  # noqa: E402
from securedns import net_config  # noqa: E402
from securedns import pihole_consultas, publicador  # noqa: E402
from securedns.pihole_api import ClientePihole  # noqa: E402
from securedns.view_prefs import PreferenciasDeVista  # noqa: E402
from securedns.hallazgos import HallazgosNormales  # noqa: E402


def _update_feeds_in_background(
    min_interval_hours: float, blocklist: Blocklist, include_ad_tracker: bool = False
) -> None:
    try:
        updated = update_blocklist.main(
            force=False, min_interval_hours=min_interval_hours, include_ad_tracker=include_ad_tracker
        )
        if updated:
            blocklist.reload()
            print("[SecureDNS] lista de amenazas actualizada y recargada en caliente.")
    except Exception as exc:  # noqa: BLE001
        print(f"[SecureDNS] no se pudo actualizar la blocklist automática: {exc}")


def _light_reload_loop(blocklist: Blocklist, allowlist: Allowlist, noise_list=None) -> None:
    while True:
        time.sleep(LIGHT_RELOAD_INTERVAL_SECONDS)
        try:
            blocklist.reload()
            allowlist.reload()
            if noise_list is not None:
                noise_list.reload()
        except Exception as exc:  # noqa: BLE001 - no debe tumbar el resolver por esto
            print(f"[SecureDNS] error recargando listas: {exc}")


def _mantener_historial(logger_db: LoggerDB) -> None:
    """Resume y recorta el historial. Corre ANTES de empezar a atender.

    Por qué antes y no en un hilo de fondo, que era como estaba: `prune` y el
    VACUUM que le sigue toman el lock de la base, y `log_query` -que está en el
    camino de cada consulta DNS- necesita ese mismo lock. Medido sobre una base
    de 111 MB, el recorte tarda casi 3 segundos y el VACUUM medio segundo más:
    corriendo en paralelo con el servicio, toda la casa se quedaba sin resolver
    nombres durante ese rato, justo al prender la máquina.

    Corriendo antes de levantar el servidor, ese tiempo es tiempo de arranque:
    el resolver tarda unos segundos más en estar listo, y una vez listo anda
    bien. Es la diferencia entre "todavía no arrancó" y "anda mal".

    El problema aparece justo en las instalaciones que ya vienen usándose hace
    rato, que son las que tienen la base más grande.
    """
    try:
        dias = logger_db.consolidar_dias()
        if dias:
            print(f"[SecureDNS] se resumieron {dias} días del historial.")
        borradas = logger_db.prune()
        if borradas:
            print(f"[SecureDNS] historial recortado: {borradas:,} consultas viejas borradas.".replace(",", "."))
            logger_db.compact()
            print("[SecureDNS] base de logs compactada.")
    except Exception as exc:  # noqa: BLE001 - el mantenimiento no debe tumbar el resolver
        print(f"[SecureDNS] no se pudo recortar el historial: {exc}")


def _consolidar_periodicamente(logger_db: LoggerDB) -> None:
    """Suma al resumen diario cada hora, para que el recorte tenga qué borrar.

    Es barato (solo mira lo que entró desde la última vez) y es lo que permite
    que `prune` pueda hacer su trabajo: el recorte solo borra filas ya
    consolidadas, así que sin esto la base crecería igual.
    """
    while True:
        time.sleep(3600)
        try:
            logger_db.consolidar_dias()
        except Exception as exc:  # noqa: BLE001
            print(f"[SecureDNS] no se pudo resumir el historial: {exc}")


def _publicar_periodicamente(cfg) -> None:
    """Le deja a Pi-hole las listas de Secure-Intel, cada tantas horas.

    Corre en su propio hilo y nunca lanza: que Pi-hole esté apagado o que la
    carpeta no tenga permiso no puede tumbar el panel. El publicador ya se
    niega solo a publicar una lista vacía o encogida, así que este bucle no
    tiene que decidir nada.
    """
    espera = max(600.0, float(cfg.pihole.horas_entre_publicaciones) * 3600.0)
    while True:
        cliente = ClientePihole(cfg.pihole.url, cfg.pihole_password,
                                verificar_tls=cfg.pihole.verificar_tls)
        try:
            informe = publicador.publicar(cfg, cliente)
            print(f"[SecureDNS] Pi-hole: {informe['detalle']}")
        except Exception as exc:  # noqa: BLE001
            print(f"[SecureDNS] no pude publicar en Pi-hole: {exc}")
        finally:
            cliente.salir()
        time.sleep(espera)


def _importar_periodicamente(cfg, logger_db, blocklist, vista) -> None:
    """Trae las consultas de Pi-hole cada pocos minutos.

    La categoría se calcula contra NUESTRAS listas: Pi-hole sabe que bloqueó
    pero no si fue malware, phishing o publicidad, porque gravity mezcla todas
    las listas en una sola bolsa. Eso es lo que hace que lo importado sea
    material nuestro y no una copia.
    """
    def categoria_de(dominio: str) -> str:
        return blocklist.categoria_de(dominio) if blocklist.is_blocked(dominio) else ""

    es_ruido = vista.es_ruidoso if vista is not None else None
    espera = max(60.0, float(cfg.pihole.minutos_entre_importaciones) * 60.0)
    while True:
        try:
            informe = pihole_consultas.importar(
                cfg, logger_db, categoria_de=categoria_de, es_ruido=es_ruido)
            if informe.get("importadas") or not informe.get("ok"):
                print(f"[SecureDNS] {informe['detalle']}")
        except Exception as exc:  # noqa: BLE001
            # Una vuelta que falla no puede matar el bucle: la siguiente
            # arranca desde la misma marca de agua y no se pierde nada.
            print(f"[SecureDNS] la importación desde Pi-hole falló: {exc}")
        time.sleep(espera)


def main() -> None:
    cfg = load_config()

    blocklist_paths = [
        str(cfg.resolve_path(cfg.filtering.blocklist_path)),
        str(cfg.resolve_path(cfg.filtering.feeds_blocklist_path)),
    ]
    if cfg.filtering.enable_ad_tracker_blocklist:
        blocklist_paths.append(str(cfg.resolve_path(cfg.filtering.ad_tracker_blocklist_path)))
    blocklist = Blocklist(blocklist_paths)
    allowlist = Allowlist(str(cfg.resolve_path(cfg.filtering.allowlist_path)))
    logger_db = LoggerDB(
        str(cfg.resolve_path(cfg.logging.db_path)), max_rows=cfg.logging.max_rows
    )

    # Filtro de VISTA: qué dominios tapan el panel. No decide nada de lo que
    # se bloquea, por eso se arma acá afuera y no dentro del resolver.
    noise_list = Blocklist(str(cfg.resolve_path(cfg.dashboard.noisy_domains_path)))
    vista = PreferenciasDeVista(noise_list, ocultar_ruido=cfg.dashboard.hide_noise)
    # Se recalcula la marca sobre el historial que ya existía: así una base
    # vieja, o una lista editada a mano, quedan consistentes desde el primer
    # refresco del panel en vez de esperar a que pase tráfico nuevo.
    cambios = logger_db.remarcar_ruido(vista.es_ruidoso)
    if cambios:
        print(f"[SecureDNS] se remarcaron {cambios:,} consultas del historial".replace(",", "."))

    # Hallazgos de detección ya revisados. Es una lista de triage, no de
    # filtrado: silencia el hallazgo y su descuento de puntaje, y no participa
    # de ninguna decisión de bloqueo. Ver src/securedns/hallazgos.py.
    normales = HallazgosNormales(
        str(cfg.resolve_path(cfg.dashboard.normal_findings_path))
    )

    # Igual que el remarcado: una base que ya venía usándose no tiene el
    # dominio padre calculado, y sin eso la detección de tunneling arrancaría
    # ciega sobre todo el historial viejo.
    padres = logger_db.recalcular_padres()
    if padres:
        print(f"[SecureDNS] se completó el dominio padre de {padres:,} consultas".replace(",", "."))
    if cfg.dashboard.hide_noise:
        print(
            f"[SecureDNS] filtro de ruido del panel: {len(noise_list.dominios())} "
            "dominios de telemetría y comprobación ocultos (se apaga desde el panel)"
        )

    geoip = GeoIP(str(cfg.resolve_path(cfg.intel.geoip_db_path)))
    if geoip.disponible:
        print(f"[SecureDNS] geolocalización: {geoip.cantidad_de_rangos():,} rangos cargados".replace(",", "."))
    else:
        print("[SecureDNS] geolocalización: sin base (corré scripts/update_geoip.py)")

    rdap = ClienteRDAP(cfg.intel.rdap_enabled, str(cfg.resolve_path(cfg.intel.rdap_cache_path)))
    if cfg.intel.rdap_enabled:
        print("[SecureDNS] edad de dominios por RDAP: activada (solo para hallazgos)")

    # ---- quién resuelve, y por lo tanto qué se levanta ----
    info = modo_dns.descripcion(cfg)
    resuelve_pihole = info["modo"] == modo_dns.PIHOLE

    if resuelve_pihole:
        # No se construye el resolutor. No es solo para ahorrar memoria: si se
        # construyera, el panel mostraría un caché con entradas y un upstream
        # configurado que no está atendiendo ni una consulta. Un panel que
        # describe un resolutor apagado es peor que uno que no lo muestra.
        resolver = modo_dns.ResolutorJubilado()
    else:
        resolver = ThreatIntelResolver(
            blocklist=blocklist,
            logger_db=logger_db,
            upstream_primary=cfg.dns.upstream_primary,
            upstream_fallback=cfg.dns.upstream_fallback,
            upstream_timeout=cfg.dns.upstream_timeout,
            min_cache_ttl=cfg.dns.min_cache_ttl,
            allowlist=allowlist,
            upstream_mode=cfg.dns.upstream_mode,
            upstream_primary_tls_name=cfg.dns.upstream_primary_tls_name,
            upstream_fallback_tls_name=cfg.dns.upstream_fallback_tls_name,
            dot_fallback_to_udp=cfg.dns.dot_fallback_to_udp,
            vista=vista,
            block_mode=cfg.filtering.block_mode,
            geoip=geoip,
        )

    # Lo que levanta el botón "Apagar resolver" del panel. Se hace con un
    # evento y no mandándose una señal a sí mismo porque en Windows no hay
    # forma limpia de mandarle SIGINT a un proceso puntual: CTRL_C_EVENT va al
    # grupo de consola entero. Con el evento, el camino de apagado es el mismo
    # que el de Ctrl+C en los dos sistemas.
    detener = threading.Event()

    dns_server = (None if resuelve_pihole
                  else build_dns_server(cfg.dns.host, cfg.dns.port, resolver))
    dashboard_server = build_dashboard_server(
        cfg.dashboard.host, cfg.dashboard.port, logger_db, allowlist, blocklist, resolver,
        vista=vista, apagar=detener.set, rdap=rdap, normales=normales,
    )

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))

    print(f"[SecureDNS] {info['titulo']}")
    if resuelve_pihole:
        print(f"[SecureDNS] {info['detalle']}")
        # Decir qué NO está funcionando es la mitad del trabajo. Sin esta
        # línea, alguien lee "SecureDNS arrancó" y da por hecho que hay un
        # resolutor propio filtrando, que es justo lo que no hay.
        print("[SecureDNS] en este modo NO aplica: " + ", ".join(info["no_aplica"]))
        print(f"[SecureDNS] Pi-hole: {cfg.pihole.url}")
        print(f"[SecureDNS] consultas de Pi-hole: {cfg.pihole.base_consultas}")
    else:
        print(f"[SecureDNS] resolver escuchando en {cfg.dns.host}:{cfg.dns.port} (UDP)")
        if cfg.dns.upstream_mode == "dot":
            como = "DNS-over-TLS (cifrado, puerto 853)"
            if cfg.dns.dot_fallback_to_udp:
                como += " con respaldo UDP plano"
        else:
            como = "UDP texto plano (puerto 53)"
        print(f"[SecureDNS] modo upstream: {como}")
        print(f"[SecureDNS] upstream primario: {cfg.dns.upstream_primary} (Quad9)")
        print(f"[SecureDNS] upstream de respaldo: {cfg.dns.upstream_fallback} (Cloudflare)")
    print(f"[SecureDNS] dashboard: http://{cfg.dashboard.host}:{cfg.dashboard.port}/")
    print(f"[SecureDNS] logs: {cfg.resolve_path(cfg.logging.db_path)}")
    print(f"[SecureDNS] PID: {os.getpid()} (guardado en {PID_FILE})")
    print("[SecureDNS] Ctrl+C para detener (o 'python scripts/stop_dns.py' si corre en segundo plano).")

    update_thread = threading.Thread(
        target=_update_feeds_in_background,
        args=(cfg.filtering.feeds_update_interval_hours, blocklist, cfg.filtering.enable_ad_tracker_blocklist),
        daemon=True,
    )
    update_thread.start()

    dashboard_thread = threading.Thread(target=dashboard_server.serve_forever, daemon=True)
    dashboard_thread.start()

    light_reload_thread = threading.Thread(
        target=_light_reload_loop, args=(blocklist, allowlist, noise_list), daemon=True
    )
    light_reload_thread.start()

    # Sincrónico y ANTES de levantar el servidor DNS: ver el docstring. Este
    # es el único trabajo pesado sobre la base y no puede pisarse con el
    # servicio.
    _mantener_historial(logger_db)

    threading.Thread(
        target=_consolidar_periodicamente, args=(logger_db,), daemon=True
    ).start()

    if cfg.intel.alerts_enabled:
        escritorio = DesktopNotifier(True, solo_graves=True)
        telegram = TelegramNotifier(
            cfg.intel.telegram_enabled, cfg.telegram_bot_token, cfg.telegram_chat_id
        )
        motor = MotorDeAlertas(logger_db, telegram=telegram, escritorio=escritorio)
        motor.correr_en_segundo_plano()
        canales = []
        if escritorio.disponible:
            canales.append("escritorio")
        if telegram.enabled:
            canales.append("Telegram")
        print(
            "[SecureDNS] avisos por umbral: "
            + (", ".join(canales) if canales else "sin canales disponibles")
        )

    if resuelve_pihole:
        # Los dos hilos que reemplazan al resolutor: uno le deja las listas a
        # Pi-hole y el otro le trae las consultas para analizarlas acá.
        threading.Thread(target=_publicar_periodicamente, args=(cfg,),
                         daemon=True).start()
        if cfg.pihole.importar_consultas:
            threading.Thread(target=_importar_periodicamente,
                             args=(cfg, logger_db, blocklist, vista),
                             daemon=True).start()
            print(f"[SecureDNS] importando de Pi-hole cada "
                  f"{cfg.pihole.minutos_entre_importaciones} minutos")

    if dns_server is not None:
        dns_server.start_thread()
    try:
        # Se sale del bucle por tres caminos: Ctrl+C, el botón del panel, o
        # que el servidor DNS se haya muerto solo. Los tres terminan en el
        # mismo `finally`, así que el cierre es idéntico. En modo Pi-hole no
        # hay servidor que se pueda morir, así que solo quedan los dos
        # primeros.
        while not detener.wait(0.5):
            if dns_server is not None and not dns_server.isAlive():
                break
        if detener.is_set():
            print("\n[SecureDNS] apagando por pedido del panel...")
    except KeyboardInterrupt:
        print("\n[SecureDNS] deteniendo...")
    finally:
        if dns_server is not None:
            dns_server.stop()
        dashboard_server.shutdown()
        if PID_FILE.exists():
            PID_FILE.unlink()
        # Antes de irse: devolver el DNS del sistema a automático.
        #
        # Sin esto, apagar el resolver dejaba a Windows apuntando a un
        # 127.0.0.1 donde ya no escucha nadie, así que no resolvía ningún
        # nombre y parecía que se había caído el wifi. Solo la opción 2 del
        # .bat lo restauraba; apagar desde SecureCenter, con Ctrl+C o desde
        # el panel, no. Ahora lo hace el propio resolver, salga por donde
        # salga, y solo sobre los adaptadores que apuntan a él.
        #
        # `devolver_el_dns_si_corresponde` y no `restaurar_e_informar` a
        # secas: en modo Pi-hole nunca tocamos el adaptador, así que
        # restaurarlo al salir sería manotear la configuración de red de una
        # máquina donde el DNS lo administra otro.
        if cfg.dns.port == 53:
            net_config.devolver_el_dns_si_corresponde()
        print("[SecureDNS] listo, todo cerrado.")


if __name__ == "__main__":
    main()
