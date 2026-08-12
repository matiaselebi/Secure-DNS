"""Dashboard web para ver qué está resolviendo el DNS y administrar sus
listas.

Corre como un servidor HTTP aparte (el DNS habla su propio protocolo por
UDP/TCP en el puerto 53, no HTTP), con el mismo estilo visual, las mismas
convenciones y las mismas defensas que el panel de SecureProxy.

Sobre las defensas, que no son decorativas aunque el panel escuche solo en
127.0.0.1: un panel local es alcanzable desde cualquier página web que
visites. Ver `_origen_confiable` y `_host_permitido`.
"""

import csv
import html as html_lib
import io
import json
import threading
import time
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

from .blocklist import Allowlist, Blocklist, nombre_de_categoria
from .deteccion import dominio_padre
from .dns_server import ThreatIntelResolver
from .logger_db import LoggerDB
from .puntaje import calcular as calcular_puntaje
from .validation import is_valid_domain, limpiar_para_mostrar, normalizar_dominio


def _miles(n) -> str:
    """12345 -> "12.345". Separador de miles con punto, como se escribe acá."""
    try:
        return f"{int(n):,}".replace(",", ".")
    except (TypeError, ValueError):
        return str(n)


def formatear_fecha(iso: str) -> str:
    """Convierte el timestamp guardado a algo legible y EN HORA LOCAL.

    En la base se guarda en UTC y en ISO completo
    ("2026-07-27T00:09:15.704172+00:00") porque así se ordena bien y no
    depende de la zona horaria de la máquina. Pero mostrarlo tal cual es
    ilegible, y encima confunde: no es la hora que marca tu reloj. Este es
    exactamente el problema que tenía este panel, que mostraba UTC con un
    "(UTC)" al lado como disculpa.
    """
    try:
        momento = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return str(iso)
    if momento.tzinfo is None:
        momento = momento.replace(tzinfo=timezone.utc)
    return momento.astimezone().strftime("%d/%m/%Y %H:%M:%S")


def hora_local(clave_utc: str) -> str:
    """Pasa la clave horaria del agrupamiento ("2026-07-29T05") a hora local.

    El agrupamiento se hace sobre el timestamp guardado, que está en UTC. Sin
    esta conversión las barras del gráfico quedan corridas respecto de la
    tabla del historial, que sí muestra hora local, y las dos hablarían de
    cosas distintas.

    Se muestra HH:00 y no HH:MM porque cada barra ES una hora entera: los
    minutos serían siempre cero y darían una idea falsa de precisión.
    """
    try:
        momento = datetime.fromisoformat(f"{clave_utc}:00:00+00:00")
    except (TypeError, ValueError):
        return str(clave_utc)
    return momento.astimezone().strftime("%H:00")


PAGINA_DE_APAGADO = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>SecureDNS apagado</title>
<style>
  body { background:#0f1419; color:#e6edf3; font-family:system-ui, sans-serif;
         display:flex; align-items:center; justify-content:center;
         min-height:100vh; margin:0; }
  .caja { max-width:38rem; padding:2rem; text-align:center; }
  h1 { color:#f0883e; margin:0 0 0.6rem 0; }
  p { color:#8b949e; line-height:1.6; }
  code { background:#161b22; border:1px solid #30363d; border-radius:6px;
         padding:0.15rem 0.4rem; color:#e6edf3; white-space:nowrap;
         display:inline-block; }
</style>
</head>
<body>
  <div class="caja">
    <h1>SecureDNS apagado</h1>
    <p>El proceso se cerró solo, igual que con Ctrl+C: se guardó todo y se
       borró el archivo de PID.</p>
    <p><strong>El DNS de tu PC volvió a automático.</strong> Si los
       adaptadores estaban apuntando a este resolver, se los devolvió a DHCP y
       se vació el cache de nombres, así que podés seguir navegando. Antes esto
       no pasaba y la máquina quedaba sin resolver ningún nombre, que parece
       que se cayó el wifi pero no lo es.</p>
    <p>Si igual no navegás, lo más probable es que no haya tenido permisos de
       administrador para tocar la placa de red. Abrí PowerShell como
       administrador y pegá:
       <code>Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses }</code>
       y después <code>ipconfig /flushdns</code>.</p>
    <p>Para levantarlo de nuevo: <code>python scripts/run_dns.py</code>, o la
       opción 1 de <code>SecureDNS.bat</code>.</p>
  </div>
</body>
</html>
"""


class DashboardRequestHandler(BaseHTTPRequestHandler):
    logger_db: LoggerDB
    allowlist: Allowlist
    blocklist: Blocklist
    resolver: ThreatIntelResolver
    # Preferencias de lo que se MUESTRA (filtro de ruido). Puede no estar.
    vista = None
    # Cliente RDAP para la edad de los dominios. Puede no estar o estar
    # apagado: en los dos casos, el panel muestra todo menos la edad.
    rdap = None
    # Callable que le pide al proceso que se apague, o None si este panel no
    # tiene nada que apagar (tests, o embebido en otro programa).
    apagar = None
    # Hallazgos de detección ya revisados y marcados como normales. Ver
    # hallazgos.py. Puede no estar: entonces no se silencia nada.
    normales = None

    protocol_version = "HTTP/1.1"
    timeout = 30

    MAX_CLIENTES_SSE = 12

    _sse_lock = threading.Lock()
    _sse_clientes = 0

    # Cache de la pestaña Detección, compartido por todas las conexiones.
    #
    # Medido sobre 200.000 filas: las dos detecciones juntas tardan unos 700 ms.
    # El panel se refresca cada 5 segundos, así que sin cache el proceso se
    # pasaría el 14% del tiempo recalculando lo mismo, y con tres pestañas
    # abiertas se multiplica. Como la ventana que miran es de 24 horas, un
    # minuto de desfasaje no cambia absolutamente nada: lo que se detecta son
    # patrones de horas, no de segundos.
    _deteccion_lock = threading.Lock()
    _deteccion_cache: tuple[float, str] | None = None
    TTL_DETECCION = 60

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass

    # ---------- defensas del panel ----------

    # Rutas que CAMBIAN algo. Se separan de las de lectura porque necesitan
    # protección contra CSRF: son las que un sitio web podría disparar sin
    # que te enteres.
    RUTAS_QUE_CAMBIAN = frozenset({
        "/allow", "/unallow", "/blockdomain", "/unblockdomain",
        "/clear-cache", "/config", "/nivel", "/ocultar", "/mostrar",
        "/apagar", "/borrar-historial", "/normal", "/vigilar",
    })

    HOSTS_PERMITIDOS = frozenset({"127.0.0.1", "localhost", "[::1]", "::1"})

    def _host_permitido(self) -> bool:
        """¿El pedido llegó pidiendo por un nombre que es realmente nuestro?

        Sin esto el panel es vulnerable a DNS rebinding: un atacante publica
        `attacker.com` con TTL 0, te hace entrar, y después reapunta ese
        nombre a 127.0.0.1. A partir de ahí su JavaScript queda del MISMO
        origen que el panel para el navegador, así que puede LEER las
        respuestas. Y acá lo que hay para leer es el historial de DNS de toda
        la casa: cada nombre que consultó cada dispositivo.

        Tiene un gustito particular en este proyecto: el ataque se monta
        justamente sobre DNS, y la víctima sería el panel del resolver.

        La defensa es barata y definitiva: el navegador manda en `Host` el
        nombre que el usuario escribió. Si no es uno de los nuestros, no es
        un pedido nuestro.
        """
        host = (self.headers.get("Host") or "").strip().lower()
        # IPv6 con puerto viene como "[::1]:8890". Sacando el puerto por
        # `count(":") == 1` nunca daba, así que el panel quedaba inalcanzable
        # para quien entrara por IPv6. Se corta después del corchete.
        if host.startswith("["):
            cierre = host.find("]")
            if cierre != -1:
                return host[: cierre + 1] in self.HOSTS_PERMITIDOS
        if not host:
            # Sin header Host no puede ser un navegador: HTTP/1.1 lo exige.
            # Y sin navegador no hay DNS rebinding, que es lo que esto
            # previene. Un cliente simple (curl -0, el .bat, SecureCenter)
            # pasa.
            return True
        sin_puerto = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        return sin_puerto in self.HOSTS_PERMITIDOS or host in self.HOSTS_PERMITIDOS

    def _origen_confiable(self) -> bool:
        """¿Esta acción la pidió el panel, o la disparó otro sitio?

        El agujero que cierra: todas las acciones del panel son GET sin
        token, así que cualquier página que visites puede hacer
        `<img src="http://127.0.0.1:8890/config?k=upstream_mode&v=udp">` y
        dejar tus consultas DNS viajando en texto plano. No hace falta que
        lea la respuesta para que el daño esté hecho, así que la política de
        mismo origen del navegador no protege de esto. Y hay peores:
        `/allow?domain=su-c2.com` mete su propio dominio en la lista blanca,
        que en un resolver significa que ningún feed de amenazas lo va a
        poder frenar.

        Se chequea en dos capas, porque ninguna sola alcanza:

        1. `Sec-Fetch-Site`, que mandan los navegadores actuales y que el
           JavaScript de una página NO puede falsificar.
        2. `Origin`/`Referer` para los navegadores que no mandan el primero.

        Si no viene ninguno de los tres se acepta: es el caso de curl, del
        menú `.bat` y de los tests, que no son un navegador y por lo tanto no
        son el vector de este ataque.
        """
        sitio = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sitio:
            return sitio in ("same-origin", "none")

        for cabecera in ("Origin", "Referer"):
            valor = (self.headers.get(cabecera) or "").strip()
            if not valor:
                continue
            partes = urlsplit(valor)
            nombre = (partes.hostname or "").lower()
            return nombre in self.HOSTS_PERMITIDOS or nombre in ("127.0.0.1", "localhost", "::1")
        return True

    def _accion_autorizada(self, clean_path: str) -> bool:
        if not self._host_permitido():
            return False
        if clean_path in self.RUTAS_QUE_CAMBIAN and not self._origen_confiable():
            return False
        return True

    def _rechazar_por_origen(self) -> None:
        cuerpo = (
            "SecureDNS: pedido rechazado.\n\n"
            "El panel solo acepta pedidos hechos desde el propio panel, "
            "abierto en 127.0.0.1. Esto existe para que ninguna pagina web "
            "pueda cambiarte la configuracion del resolver sin que te enteres.\n"
        ).encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(cuerpo)
        self.close_connection = True

    # ---------- ruteo ----------

    def do_GET(self) -> None:  # noqa: N802
        parsed_path = urlsplit(self.path)
        clean_path = parsed_path.path.rstrip("/")
        self._query_actual = parse_qs(parsed_path.query)
        routes = {
            "/allow": lambda: self._handle_list_edit(self.allowlist, parsed_path.query, add=True),
            "/unallow": lambda: self._handle_list_edit(self.allowlist, parsed_path.query, add=False),
            "/blockdomain": lambda: self._handle_list_edit(self.blocklist, parsed_path.query, add=True),
            "/unblockdomain": lambda: self._handle_list_edit(self.blocklist, parsed_path.query, add=False),
            "/clear-cache": self._handle_clear_cache,
            "/borrar-historial": self._handle_borrar_historial,
            "/cache-count": self._handle_cache_count,
            "/config": lambda: self._handle_config_change(parsed_path.query),
            "/nivel": lambda: self._aplicar_nivel(
                (parse_qs(parsed_path.query).get("v") or [""])[0]
            ),
            "/ocultar": lambda: self._handle_ruido(parsed_path.query, add=True),
            "/mostrar": lambda: self._handle_ruido(parsed_path.query, add=False),
            "/normal": lambda: self._handle_normal(parsed_path.query, marcar=True),
            "/vigilar": lambda: self._handle_normal(parsed_path.query, marcar=False),
            "/apagar": self._handle_apagar,
            "/eventos": lambda: self._serve_eventos(parsed_path.query),
            "/health": self._serve_health,
            "/export.csv": lambda: self._exportar(parsed_path.query, "csv"),
            "/export.json": lambda: self._exportar(parsed_path.query, "json"),
        }
        # `/api` a secas es el índice: sin contemplarlo, entrar a la raíz de la
        # API caería en el panel HTML, que es lo más confuso posible para
        # alguien explorándola.
        if clean_path == "/api" or clean_path.startswith("/api/"):
            if not self._host_permitido():
                self._rechazar_por_origen()
                return
            self._servir_api(clean_path, parsed_path.query)
            return
        handler = routes.get(clean_path)
        # /health queda afuera del chequeo: lo consulta SecureCenter para
        # saber si el resolver está vivo, no cambia nada y no expone datos.
        if clean_path != "/health" and not self._accion_autorizada(clean_path):
            self._rechazar_por_origen()
            return
        if handler is not None:
            handler()
            return
        self._serve_dashboard()

    def _serve_health(self) -> None:
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    # ---------- configuración editable desde el dashboard ----------

    # Lista blanca explícita de lo que se puede tocar desde la web. Cada
    # opción dice si se aplica en caliente o si necesita reiniciar, y eso se
    # muestra en la página para no prometer de más.
    OPCIONES_EDITABLES = {
        "upstream_mode": {
            "seccion": "dns",
            "tipo": "opcion",
            "valores": ("dot", "udp"),
            "en_vivo": True,
        },
        "dot_fallback_to_udp": {"seccion": "dns", "tipo": "booleano", "en_vivo": True},
        "min_cache_ttl": {
            "seccion": "dns", "tipo": "numero", "min": 0, "max": 86400, "en_vivo": True,
        },
        "enable_ad_tracker_blocklist": {
            "seccion": "filtering", "tipo": "booleano", "en_vivo": False,
        },
        "hide_noise": {"seccion": "dashboard", "tipo": "booleano", "en_vivo": True},
        "block_mode": {
            "seccion": "filtering",
            "tipo": "opcion",
            "valores": ("nxdomain", "zero", "localhost"),
            "en_vivo": True,
        },
    }

    # Los tres niveles, y qué fija cada uno. Existe porque la pestaña de
    # configuración pide decidir opción por opción, y para eso hay que saber
    # qué significa cada una. Un nivel es una respuesta a "qué tan estricto
    # lo querés", que es la pregunta que la gente realmente se hace.
    NIVELES = {
        "normal": {
            "etiqueta": "Normal",
            "resumen": "Cifrado, con respaldo en texto plano si la red lo bloquea. "
                       "Filtra amenazas, no filtra publicidad.",
            "valores": {
                "upstream_mode": "dot",
                "dot_fallback_to_udp": True,
                "enable_ad_tracker_blocklist": False,
            },
        },
        "estricto": {
            "etiqueta": "Estricto",
            "resumen": "Igual que Normal pero además bloquea publicidad y rastreadores. "
                       "Alguna página puede verse distinta.",
            "valores": {
                "upstream_mode": "dot",
                "dot_fallback_to_udp": True,
                "enable_ad_tracker_blocklist": True,
            },
        },
        "paranoico": {
            "etiqueta": "Paranoico",
            "resumen": "Exige cifrado siempre: si la red bloquea el puerto 853, no se "
                       "resuelve nada. Privacidad por sobre disponibilidad.",
            "valores": {
                "upstream_mode": "dot",
                "dot_fallback_to_udp": False,
                "enable_ad_tracker_blocklist": True,
            },
        },
    }

    def _valores_actuales(self) -> dict:
        from .config_loader import PROJECT_ROOT
        from .config_writer import read_value

        cfg_file = PROJECT_ROOT / "config" / "config.yaml"
        return {
            "upstream_mode": getattr(self.resolver, "upstream_mode", "dot"),
            "dot_fallback_to_udp": bool(getattr(self.resolver, "dot_fallback_to_udp", True)),
            "enable_ad_tracker_blocklist": bool(
                read_value(cfg_file, "filtering", "enable_ad_tracker_blocklist", False)
            ),
        }

    def _nivel_actual(self) -> str:
        """Qué nivel está puesto, o "personalizado" si la combinación no
        coincide con ninguno.

        Que exista "personalizado" no es un detalle: sin eso, tocar una
        opción suelta dejaría un nivel marcado como activo mientras la
        configuración ya es otra, que es peor que no mostrar nada.
        """
        actuales = self._valores_actuales()
        for nombre, nivel in self.NIVELES.items():
            if all(actuales.get(k) == v for k, v in nivel["valores"].items()):
                return nombre
        return "personalizado"

    def _aplicar_nivel(self, nombre: str) -> None:
        nivel = self.NIVELES.get((nombre or "").strip().lower())
        if nivel is None:
            self._redirect_to_dashboard()
            return
        # Se mira ANTES de aplicar: después ya no hay con qué comparar.
        ads_antes = self._valores_actuales()["enable_ad_tracker_blocklist"]
        for clave, valor in nivel["valores"].items():
            self._guardar_opcion(clave, valor)
        aviso = f"Nivel {nivel['etiqueta']} aplicado."
        if ads_antes != nivel["valores"]["enable_ad_tracker_blocklist"]:
            # Es la única opción del nivel que no se aplica en caliente:
            # cargar (o soltar) el feed de publicidad pide reiniciar. Decirlo
            # importa, porque si no el panel muestra un nivel que todavía no
            # está del todo puesto.
            aviso += " El bloqueo de publicidad necesita reiniciar el resolver."
        self._redirect_to_dashboard(aviso)

    def _guardar_opcion(self, clave: str, valor) -> None:
        """Escribe una opción en el YAML y, si aplica en caliente, la deja
        andando ya mismo."""
        from .config_loader import PROJECT_ROOT
        from .config_writer import set_value

        spec = self.OPCIONES_EDITABLES.get(clave)
        if spec is None:
            return
        set_value(PROJECT_ROOT / "config" / "config.yaml", spec["seccion"], clave, valor)
        if not spec["en_vivo"]:
            return
        if clave == "hide_noise":
            if self.vista is not None:
                self.vista.ocultar_ruido = bool(valor)
            return
        setattr(self.resolver, clave, valor)
        if clave == "upstream_mode":
            # Al cambiar de transporte hay que soltar las conexiones TLS
            # persistentes: si no, seguirían usándose las viejas.
            #
            # Se lo pide al resolver en vez de recorrerle el diccionario desde
            # acá, que era lo que se hacía antes: eso cerraba sockets desde el
            # hilo del panel sin tomar ningún lock, mientras un hilo de
            # consulta podía estar escribiendo en ese mismo socket.
            cerrar = getattr(self.resolver, "cerrar_conexiones_tls", None)
            if cerrar is not None:
                cerrar()

    def _handle_config_change(self, query_string: str) -> None:
        params = parse_qs(query_string)
        clave = (params.get("k") or [""])[0]
        valor_crudo = (params.get("v") or [""])[0]
        spec = self.OPCIONES_EDITABLES.get(clave)
        if spec is None:
            self._redirect_to_dashboard()
            return

        if spec["tipo"] == "opcion":
            if valor_crudo not in spec["valores"]:
                self._redirect_to_dashboard()
                return
            valor = valor_crudo
        elif spec["tipo"] == "booleano":
            valor = valor_crudo.lower() in ("1", "true", "on", "si", "sí")
        else:
            try:
                valor = int(valor_crudo)
            except ValueError:
                self._redirect_to_dashboard()
                return
            if not (spec["min"] <= valor <= spec["max"]):
                self._redirect_to_dashboard()
                return

        self._guardar_opcion(clave, valor)
        self._redirect_to_dashboard()

    # ---------- acciones ----------

    def _handle_cache_count(self) -> None:
        """Solo el número de entradas del cache, en texto plano. Lo usa la
        opción "Ver estado" del menú .bat: el cache vive en memoria del
        proceso, así que no hay forma de leerlo desde afuera sin pasar por
        acá."""
        body = str(self.resolver.cache_size()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _redirect_to_dashboard(self, aviso: str = "") -> None:
        """Respuesta común para las acciones del panel: redirige de vuelta y
        cierra la conexión.

        Cerrarla explícitamente (en vez de mantener keep-alive) evita que una
        pestaña dejada en segundo plano termine intentando reusar una
        conexión que el servidor ya cerró por inactividad.
        """
        destino = "/"
        if aviso:
            destino = f"/?aviso={quote(aviso)}"
        self.send_response(303)
        self.send_header("Location", destino)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _handle_list_edit(self, target_list, query_string: str, add: bool) -> None:
        """Agrega o saca un dominio de una lista.

        Al agregar se normaliza primero: pegar "https://www.ejemplo.com/algo"
        de la barra del navegador es lo natural, y antes eso se rechazaba en
        silencio. Ahora se limpia y se avisa qué se le sacó.
        """
        params = parse_qs(query_string)
        crudo = (params.get("domain") or [""])[0].strip()
        if not crudo:
            self._redirect_to_dashboard()
            return

        if not add:
            target_list.remove_and_reload(crudo)
            self._redirect_to_dashboard()
            return

        dominio, avisos = normalizar_dominio(crudo)
        if not dominio or not is_valid_domain(dominio):
            self._redirect_to_dashboard(
                f"No pude usar «{crudo}»: no parece un dominio."
            )
            return
        target_list.add_and_reload(dominio)
        if avisos:
            self._redirect_to_dashboard(
                f"Se guardó como {dominio}: " + "; ".join(avisos) + "."
            )
        else:
            self._redirect_to_dashboard(f"Se guardó {dominio}.")

    def _handle_ruido(self, query_string: str, add: bool) -> None:
        """Suma o saca un dominio de la lista de ruido (filtro de VISTA).

        No cambia nada de lo que se bloquea: solo deja de aparecer en el
        historial y en las estadísticas. La lista que viene de fábrica cubre
        el ruido típico de sistema, pero el de cada red es distinto.
        """
        vista = self.vista
        if vista is None:
            self._redirect_to_dashboard()
            return
        params = parse_qs(query_string)
        crudo = (params.get("domain") or [""])[0].strip()
        if not crudo:
            self._redirect_to_dashboard()
            return
        dominio, _avisos = normalizar_dominio(crudo)
        # Se valida igual que en las otras listas. Sin esto, `add_and_reload`
        # escribía tal cual lo que llegara: un `domain=a.com%0Abanco.com%0A...`
        # metía varias líneas de una sola vez y sacaba del panel todos los
        # dominios que quisiera quien lo mandara. No evita ningún bloqueo,
        # porque este filtro es de vista, pero ciega al que está mirando, que
        # es el complemento perfecto de una intrusión.
        if not dominio or not is_valid_domain(dominio):
            self._redirect_to_dashboard(
                f"No pude usar «{crudo}»: no parece un dominio."
            )
            return
        if add:
            vista.agregar(dominio)
            aviso = (
                f"{dominio} ya no se muestra en el panel. Se sigue resolviendo y "
                "registrando igual."
            )
        else:
            vista.quitar(dominio)
            aviso = f"{dominio} vuelve a mostrarse en el panel."
        # El historial que ya existía se remarca en el momento, para que el
        # cambio se vea en el primer refresco y no recién con tráfico nuevo.
        self.logger_db.remarcar_ruido(vista.es_ruidoso)
        self._redirect_to_dashboard(aviso)

    def _handle_normal(self, query_string: str, marcar: bool) -> None:
        """Marca (o desmarca) un hallazgo de detección como esperable.

        No toca ninguna lista de bloqueo: el dominio se sigue resolviendo o
        bloqueando exactamente igual que antes. Lo único que cambia es que su
        patrón deja de aparecer como hallazgo y deja de restar puntaje.
        """
        normales = self.normales
        if normales is None:
            self._redirect_to_dashboard()
            return
        params = parse_qs(query_string)
        crudo = (params.get("domain") or [""])[0].strip()
        dominio, _avisos = normalizar_dominio(crudo)
        # Misma validación que en las otras listas: sin esto, un
        # `domain=a.com%0Ab.com` escribe varias líneas de un pedido y silencia
        # de golpe detecciones que nadie revisó.
        if not dominio or not is_valid_domain(dominio):
            self._redirect_to_dashboard(
                f"No pude usar «{crudo}»: no parece un dominio."
            )
            return
        if marcar:
            normales.marcar(dominio)
            aviso = (
                f"{dominio} queda marcado como normal: deja de aparecer en "
                "Detección y de restar puntaje. Se sigue filtrando y "
                "registrando igual que antes."
            )
        else:
            normales.volver_a_vigilar(dominio)
            aviso = f"{dominio} vuelve a vigilarse en Detección."
        self._olvidar_hallazgos()
        self._redirect_to_dashboard(aviso)

    def _handle_clear_cache(self) -> None:
        self.resolver.clear_cache()
        self._redirect_to_dashboard("Cache de respuestas vaciado.")

    def _handle_borrar_historial(self) -> None:
        borradas = self.logger_db.clear()
        self._redirect_to_dashboard(
            f"Historial borrado: {borradas} consultas. El archivo se compactó."
        )

    # Tope de filas que se exportan de una. Es alto a propósito (la idea es
    # llevarse el historial, no una muestra) pero existe: sin techo, una base
    # de 200.000 filas arma un CSV de decenas de MB en memoria antes de
    # mandarlo, y el panel se queda duro mientras tanto.
    MAX_EXPORTAR = 50_000

    def _exportar(self, query_string: str, formato: str) -> None:
        """Baja el historial en CSV o JSON, respetando el filtro del buscador.

        Que respete el filtro es lo que lo hace útil: lo que te llevás es lo
        que estás viendo. Exportar siempre todo obligaría a filtrar de nuevo
        afuera, que es el trabajo que el panel ya hizo.
        """
        self._query_actual = parse_qs(query_string)
        consulta = (self._query_actual.get("q") or [""])[0].strip()
        filtros = self._filtros_actuales()
        # Cuando hay búsqueda o filtros se exporta todo lo que coincide
        # (resueltas y bloqueadas); sin nada puesto, solo los bloqueos, que es
        # lo que muestra el historial por defecto.
        filas = self.logger_db.buscar(
            texto=consulta,
            solo_bloqueadas=not consulta and not any(filtros.values()),
            limit=self.MAX_EXPORTAR,
            ocultar=self._ocultar_ruido(),
            **filtros,
        )
        # La hora se exporta en local, igual que en pantalla: un CSV que dice
        # una hora distinta de la que viste en el panel es una trampa.
        for fila in filas:
            fila["timestamp"] = formatear_fecha(fila["timestamp"])

        if formato == "json":
            cuerpo = json.dumps(filas, ensure_ascii=False, indent=2).encode("utf-8")
            tipo = "application/json; charset=utf-8"
            nombre = "securedns-historial.json"
        else:
            buffer = io.StringIO()
            escritor = csv.DictWriter(buffer, fieldnames=list(self.logger_db.COLUMNAS))
            escritor.writeheader()
            for fila in filas:
                escritor.writerow(fila)
            # BOM para que Excel abra el archivo en UTF-8 en vez de romper los
            # acentos. Sin esto, "México" se ve "MÃ©xico".
            cuerpo = ("﻿" + buffer.getvalue()).encode("utf-8")
            tipo = "text/csv; charset=utf-8"
            nombre = "securedns-historial.csv"

        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Disposition", f'attachment; filename="{nombre}"')
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(cuerpo)
        self.close_connection = True

    # ---------- API de solo lectura ----------
    #
    # Por qué existe, más allá de que quede lindo en el README: hoy las tres
    # herramientas de la suite no tienen ningún contrato entre ellas.
    # SecureCenter necesita leer el estado de cada una, y la alternativa a una
    # API es que raspe el HTML del panel, que se rompe con cada cambio de
    # diseño. Si esta forma se porta después a SecureProxy y a SecureVPN, el
    # problema queda resuelto para la suite entera.
    #
    # Es de SOLO LECTURA a propósito. Todo lo que cambia algo sigue estando en
    # el panel, detrás del chequeo anti-CSRF. Una API que además escribiera
    # necesitaría autenticación de verdad, y meter un esquema de tokens en un
    # servicio que escucha en 127.0.0.1 es más superficie de la que resuelve.
    #
    # No se manda `Access-Control-Allow-Origin`, y eso es deliberado: sin ese
    # header el navegador no deja que una página de otro origen LEA las
    # respuestas. Agregarlo por comodidad abriría el historial de DNS de toda
    # la casa a cualquier sitio que visites.

    def _servir_api(self, ruta: str, query: str) -> None:
        params = parse_qs(query)
        ocultar = self._ocultar_ruido()

        def entero(nombre: str, por_defecto: int, tope: int) -> int:
            try:
                return max(1, min(tope, int((params.get(nombre) or [""])[0])))
            except (TypeError, ValueError):
                return por_defecto

        recursos = {
            "/api": lambda: {
                "servicio": "SecureDNS",
                "recursos": [
                    "/api/estado", "/api/historial", "/api/estadisticas",
                    "/api/detecciones", "/api/clientes", "/api/listas",
                ],
                "nota": "Solo lectura. Todo lo que cambia algo va por el panel.",
            },
            "/api/estado": self._api_estado,
            "/api/historial": lambda: {
                "consultas": self.logger_db.buscar(
                    texto=(params.get("q") or [""])[0].strip(),
                    solo_bloqueadas=(params.get("bloqueadas") or ["0"])[0] == "1",
                    limit=entero("limite", 100, 1000),
                    ocultar=ocultar,
                ),
            },
            "/api/estadisticas": lambda: {
                **self.logger_db.stats(ocultar=ocultar),
                "latencia": self.logger_db.latencia(ocultar=ocultar),
                "dnssec": self.logger_db.dnssec(ocultar=ocultar),
                "por_categoria": [
                    {"categoria": c, "cantidad": n}
                    for c, n in self.logger_db.bloqueos_por_categoria(ocultar=ocultar)
                ],
                "top_dominios": [
                    {"dominio": d, "cantidad": n}
                    for d, n in self.logger_db.top_dominios(10, ocultar=ocultar)
                ],
            },
            "/api/detecciones": lambda: dict(
                zip(("tunneling", "actividad_anomala"), self._hallazgos())
            ),
            "/api/clientes": lambda: {
                "clientes": [
                    {"ip": ip, "consultas": total, "bloqueadas": bloq}
                    for ip, total, bloq in self.logger_db.top_clientes(
                        entero("limite", 20, 200), ocultar=ocultar,
                    )
                ],
            },
            "/api/listas": lambda: {
                "lista_negra_manual": self.blocklist.manual_entries(),
                "lista_blanca": self.allowlist.manual_entries(),
                "ocultos_del_panel": (
                    self.vista.dominios_manuales() if self.vista else []
                ),
            },
        }

        armar = recursos.get(ruta)
        if armar is None:
            self._responder_json({
                "error": "recurso desconocido",
                "recursos": sorted(recursos),
            }, codigo=404)
            return
        try:
            self._responder_json(armar())
        except Exception:  # noqa: BLE001 - la API no puede tumbar el panel
            # Sin el texto de la excepción: filtraba rutas del filesystem y
            # detalles internos a cualquier proceso local. Para diagnosticar
            # está el traceback en la consola del resolver, que es donde tiene
            # que estar.
            self._responder_json({"error": "no se pudo armar la respuesta"}, codigo=500)
            traceback.print_exc()

    def _api_estado(self) -> dict:
        """Lo mínimo que SecureCenter necesita para una tarjeta de estado."""
        stats = self.logger_db.stats(ocultar=self._ocultar_ruido())
        resolver = self.resolver
        return {
            "servicio": "SecureDNS",
            "vivo": True,
            "modo_upstream": getattr(resolver, "upstream_mode", ""),
            "respaldo_en_texto_plano": bool(getattr(resolver, "dot_fallback_to_udp", True)),
            "modo_de_bloqueo": getattr(resolver, "block_mode", ""),
            "entradas_en_cache": resolver.cache_size(),
            "consultas": stats["total_queries"],
            "bloqueadas": stats["blocked_queries"],
            "tasa_de_bloqueo": (
                stats["blocked_queries"] / stats["total_queries"] * 100
                if stats["total_queries"] else 0.0
            ),
            # Del cache compartido, no recalculados: ver `_hallazgos`.
            "hallazgos_abiertos": sum(len(x) for x in self._hallazgos()),
        }

    def _responder_json(self, datos: dict, codigo: int = 200) -> None:
        cuerpo = json.dumps(datos, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        # Que ningún navegador ni intermediario guarde el historial de DNS.
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(cuerpo)
        self.close_connection = True

    def _handle_apagar(self) -> None:
        """Endpoint del botón "Apagar resolver": corta el proceso entero.

        Mismo mecanismo que en SecureProxy: no se manda una señal (en Windows
        no hay forma limpia de mandarle SIGINT a un proceso puntual), sino que
        se levanta un evento que el hilo principal está esperando, y ese hilo
        hace el mismo cierre ordenado que con Ctrl+C.

        Primero se contesta y recién después se apaga: al revés, el proceso
        podía morir antes de que la respuesta llegara y el navegador mostraba
        un error justo cuando la acción había funcionado bien.
        """
        if not callable(type(self).apagar):
            self._redirect_to_dashboard(
                "Este resolver no se puede apagar desde el panel: no fue "
                "arrancado con scripts/run_dns.py."
            )
            return

        cuerpo = PAGINA_DE_APAGADO.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(cuerpo)
        try:
            self.wfile.flush()
        except OSError:
            pass
        self.close_connection = True

        pedir_apagado = type(self).apagar

        def _apagar_en_un_momento() -> None:
            time.sleep(0.5)
            pedir_apagado()

        threading.Thread(target=_apagar_en_un_momento, daemon=True).start()

    # ---------- canal de eventos (SSE) ----------

    def _fragmentos(self, consulta: str) -> dict:
        """Los pedazos de la página que cambian solos.

        La primera carga y las actualizaciones en vivo salen del MISMO
        código, así no se pueden ir separando con el tiempo.

        `revision` es una huella barata de lo que se está mostrando: si no
        cambió, no se manda nada por el canal y el navegador no toca el DOM.
        """
        ocultar = self._ocultar_ruido()
        stats = self.logger_db.stats(ocultar=ocultar)
        filtros = self._filtros_actuales()
        filas = self.logger_db.buscar(
            texto=consulta,
            solo_bloqueadas=not consulta and not any(filtros.values()),
            limit=50, ocultar=ocultar, **filtros,
        )
        tarjetas = self._render_tarjetas(stats)
        historial = self._render_filas(filas, consulta)
        estadisticas = self._render_estadisticas(ocultar)
        deteccion = self._render_deteccion()
        resumen = self._render_resumen()
        ruido = self._render_aviso_de_ruido(stats, ocultar)
        return {
            "tarjetas": tarjetas,
            "ruido": ruido,
            "historial": historial,
            "estadisticas": estadisticas,
            "deteccion": deteccion,
            "resumen": resumen,
            # Cuántas filas se encontraron de verdad. Antes esto se contaba
            # sobre el HTML buscando "<tr>", y al sumarse la fila de detalle
            # cada consulta pasó a valer dos: el panel decía el doble.
            "encontradas": len(filas),
            "revision": hash(
                (tarjetas, historial, estadisticas, deteccion, resumen, ruido)
            ),
        }

    def _serve_eventos(self, query_string: str) -> None:
        """Canal de eventos (SSE): el servidor deja la respuesta abierta y va
        mandando los fragmentos cuando cambian.

        Por qué SSE y no WebSockets: esto es tráfico en UNA sola dirección
        -el servidor avisa, el navegador muestra- y para eso SSE es HTTP
        común, sin handshake ni enmarcado, así que sale con la librería
        estándar y sin dependencias nuevas.

        Reemplaza al `<meta refresh>` de cada 5 segundos, cuyo problema no era
        la frecuencia sino que recargaba la página entera: reseteaba el
        scroll, volvía a la primera pestaña y borraba lo que estuvieras
        escribiendo en el buscador.
        """
        base = DashboardRequestHandler
        with base._sse_lock:
            if base._sse_clientes >= self.MAX_CLIENTES_SSE:
                self.send_error(503, "demasiadas pestañas abiertas")
                return
            base._sse_clientes += 1

        # El canal de eventos tiene que ver los MISMOS filtros que la página,
        # no solo el texto de búsqueda. Sin esto, ponías un filtro, y cinco
        # segundos después la primera actualización en vivo te lo pisaba con
        # el historial sin filtrar: el filtro parecía no funcionar.
        self._query_actual = parse_qs(query_string)
        consulta = (self._query_actual.get("q") or [""])[0].strip()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

            ultima_revision = None
            latido = 0
            while True:
                datos = self._fragmentos(consulta)
                if datos["revision"] != ultima_revision:
                    ultima_revision = datos["revision"]
                    payload = json.dumps(datos, ensure_ascii=False)
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    latido = 0
                else:
                    latido += 1
                    # Comentario cada ~30s: mantiene viva la conexión y, si el
                    # navegador ya se fue, es lo que lo detecta (falla el
                    # write y se corta el hilo en vez de quedar colgado).
                    if latido >= 6:
                        self.wfile.write(b": latido\n\n")
                        self.wfile.flush()
                        latido = 0
                time.sleep(5)
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            # La pestaña se cerró: es lo normal, no un error.
            pass
        finally:
            with base._sse_lock:
                base._sse_clientes -= 1

    # ---------- render ----------

    def _ocultar_ruido(self) -> bool:
        vista = self.vista
        return bool(vista is not None and getattr(vista, "ocultar_ruido", False))

    def _render_tarjetas(self, stats: dict) -> str:
        total = stats["total_queries"]
        blocked = stats["blocked_queries"]
        cached = stats["cached_queries"]
        tasa = (blocked / total * 100) if total else 0.0
        tarjetas = [
            (_miles(total), "Consultas totales"),
            (_miles(blocked), "Bloqueadas"),
            (f"{tasa:.1f}%", "Tasa de bloqueo"),
            (_miles(cached), "Respondidas desde caché"),
            (str(self.resolver.cache_size()), "Entradas en cache ahora"),
        ]
        return "".join(
            f"<div class='card'><div class='value'>{valor}</div>"
            f"<div class='label'>{etiqueta}</div></div>"
            for valor, etiqueta in tarjetas
        )

    def _render_aviso_de_ruido(self, stats: dict, ocultar: bool) -> str:
        """El cartel que dice cuántas consultas está tapando el filtro.

        Es la regla que hace honesto al filtro: un panel de seguridad que
        esconde cosas sin decir cuántas es un panel que miente.
        """
        if not ocultar:
            return ""
        ocultas = stats.get("hidden_queries", 0)
        if not ocultas:
            return ""
        cuantos = self.vista.cantidad_de_dominios if self.vista else 0
        return (
            f"<p class='aviso-ruido'>Se están ocultando <strong>{_miles(ocultas)}"
            f"</strong> consultas de {cuantos} dominios de telemetría y "
            "comprobación. Siguen registradas y el buscador las encuentra igual. "
            "Se apaga en Configuración.</p>"
        )

    # De dónde salió la respuesta, en castellano. El valor crudo que se guarda
    # ("upstream_primary_dot") es útil en la base y en el CSV, pero en pantalla
    # no se entiende.
    NOMBRES_DE_ORIGEN = {
        "cache": "caché local",
        "blocklist": "bloqueado por lista",
        "upstream_primary": "upstream primario (sin cifrar)",
        "upstream_fallback": "upstream de respaldo (sin cifrar)",
        "upstream_primary_dot": "upstream primario por TLS",
        "upstream_fallback_dot": "upstream de respaldo por TLS",
        "error": "ningún upstream respondió",
    }

    def _render_detalle(self, fila: dict) -> str:
        """Todo lo que se sabe de una consulta, desplegable desde el historial.

        Va embebido en la página en vez de pedirse al servidor al hacer clic:
        son 50 filas, pesa nada, y así abre al instante sin recargar ni perder
        la búsqueda que tengas puesta.
        """
        dominio = str(fila["domain"] or "")
        origen = str(fila["source"] or "")
        categoria = str(fila.get("category") or "")
        bloqueada = bool(fila["blocked"])
        datos = [
            ("Nombre consultado", dominio, ""),
            ("Dominio padre", dominio_padre(dominio), ""),
            ("Tipo de registro", str(fila["qtype"] or ""), ""),
            ("Equipo que consultó", str(fila["client_ip"] or ""), ""),
            ("Fecha y hora", formatear_fecha(fila["timestamp"]), ""),
            # El estado va con color: es lo primero que uno busca al abrir el
            # detalle, y en gris se pierde entre las otras quince líneas.
            ("Resultado", "bloqueada" if bloqueada else "resuelta",
             "malo" if bloqueada else "bueno"),
            ("De dónde salió la respuesta",
             self.NOMBRES_DE_ORIGEN.get(origen, origen or "sin dato"), ""),
            ("Cuánto tardó", self._ms(fila["duration_ms"]), ""),
        ]
        if fila.get("dest_ip"):
            datos.append(("Resolvió a", str(fila["dest_ip"]), ""))
        elif bloqueada:
            datos.append((
                "Resolvió a",
                "no aplica: se bloqueó antes de salir a preguntar", "",
            ))
        # Se muestran solo si están: que falte el país no significa lo mismo
        # que "no hay base descargada", puede ser una IP privada o un tipo de
        # consulta que no devuelve direcciones.
        for etiqueta, clave in (
            ("País del destino", "country"),
            ("ASN", "asn"),
            ("Proveedor", "provider"),
        ):
            datos.append((etiqueta, str(fila.get(clave) or "-"), ""))
        if not bloqueada and str(fila["source"] or "") != "error":
            datos.append((
                "DNSSEC",
                "el upstream validó la firma" if fila.get("dnssec")
                else "sin firma validada (la mayoría de internet todavía no firma)",
                "bueno" if fila.get("dnssec") else "",
            ))
        if bloqueada:
            datos.append(("Categoría", nombre_de_categoria(categoria) if categoria
                          else "sin clasificar", ""))
        datos.append(("Motivo", str(fila["reason"] or "-"),
                      "malo" if bloqueada and fila["reason"] else ""))
        if fila["noisy"]:
            datos.append((
                "Filtro de ruido",
                "marcada como telemetría: no aparece en las estadísticas mientras "
                "el filtro esté activo, pero se registró igual", "",
            ))
        datos.append(("ID en el historial", str(fila.get("id") or "-"), ""))
        filas_html = "".join(
            f"<div class='detalle-fila'><span class='detalle-clave'>{clave}</span>"
            f"<span class='detalle-valor {estilo}'>{html_lib.escape(str(valor))}</span></div>"
            for clave, valor, estilo in datos
        )
        return f"<div class='detalle-caja'>{filas_html}</div>"

    def _render_filas(self, filas: list[dict], consulta: str) -> str:
        if not filas:
            vacio = (
                "No hay consultas que coincidan con la búsqueda."
                if consulta else "Todavía no se bloqueó ninguna consulta."
            )
            return f"<tr><td colspan='6'>{vacio}</td></tr>"

        partes = []
        for fila in filas:
            dominio = str(fila["domain"] or "")
            bloqueada = bool(fila["blocked"])
            estado = (
                "<span class='pill off-red'>bloqueada</span>" if bloqueada
                else "<span class='pill on'>resuelta</span>"
            )
            # El dominio va en un atributo data- y NO interpolado dentro del
            # onclick. Es el mismo XSS que tenía SecureProxy: el navegador
            # decodifica las entidades HTML ANTES de que el parser de
            # JavaScript vea el código, así que escapar con html.escape no
            # alcanza en un atributo de evento. Un dominio con una comilla
            # cerraba el string y lo que seguía se ejecutaba.
            # El color de cada link dice qué hace la acción, no la decora:
            # verde deja pasar, ámbar corta, rojo saca de la vista, azul solo
            # mira. Ver el comentario del CSS.
            acciones = (
                f"<a class='accion-permitir' href=\"/allow?domain={quote(dominio)}\" "
                f"data-dominio='{html_lib.escape(dominio)}' "
                f"onclick=\"return confirmarAccion(this, 'permitir')\">Permitir</a>"
                if bloqueada else
                f"<a class='accion-bloquear' href=\"/blockdomain?domain={quote(dominio)}\" "
                f"data-dominio='{html_lib.escape(dominio)}' "
                f"onclick=\"return confirmarAccion(this, 'bloquear')\">Bloquear</a>"
            )
            acciones += (
                f" · <a class='accion-ocultar' href=\"/ocultar?domain={quote(dominio)}\" "
                f"data-dominio='{html_lib.escape(dominio)}' "
                f"onclick=\"return confirmarAccion(this, 'ocultar')\">Ocultar</a>"
            )
            detalle_id = f"det{fila['id']}"
            acciones += (
                f" · <a href='#' "
                f"onclick=\"return verDetalle('{detalle_id}')\">Detalle</a>"
            )
            partes.append(
                "<tr>"
                f"<td>{html_lib.escape(formatear_fecha(fila['timestamp']))}</td>"
                f"<td title='{html_lib.escape(dominio)}'>"
                f"{html_lib.escape(limpiar_para_mostrar(dominio))}</td>"
                f"<td>{html_lib.escape(str(fila['qtype'] or ''))}</td>"
                f"<td>{html_lib.escape(str(fila['client_ip'] or ''))}</td>"
                f"<td>{estado}</td>"
                f"<td>{acciones}</td>"
                "</tr>"
                f"<tr id='{detalle_id}' class='detalle'>"
                f"<td colspan='6'>{self._render_detalle(fila)}</td></tr>"
            )
        return "".join(partes)

    @staticmethod
    def _render_barras(titulo: str, datos: list[tuple[str, int]], nota: str = "") -> str:
        """Un gráfico de barras hecho con divs. Sin librerías de gráficos:
        son cinco listas ordenadas, y traer 300 KB de JavaScript para
        dibujarlas sería peor que el problema."""
        if not datos:
            return (
                f"<h3>{titulo}</h3>"
                "<p class='empty'>Todavía no hay datos suficientes.</p>"
            )
        tope = max(v for _, v in datos) or 1
        filas = "".join(
            f"<div class='barra-fila'>"
            f"<span class='barra-nombre' title='{html_lib.escape(str(k))}'>"
            f"{html_lib.escape(str(k))}</span>"
            f"<span class='barra'><span class='barra-relleno' "
            f"style='width:{max(2, int(v / tope * 100))}%'></span></span>"
            f"<span class='barra-valor'>{_miles(v)}</span></div>"
            for k, v in datos
        )
        nota_html = f"<p class='hint'>{nota}</p>" if nota else ""
        return f"<h3>{titulo}</h3>{nota_html}<div class='barras'>{filas}</div>"

    @staticmethod
    def _ms(valor: float) -> str:
        """Milisegundos legibles. Por debajo de 1 ms se muestra con decimal,
        porque decir "0 ms" para una respuesta de caché parece un error."""
        try:
            valor = float(valor or 0.0)
        except (TypeError, ValueError):
            return "0 ms"
        if valor < 10:
            return f"{valor:.1f} ms"
        return f"{valor:.0f} ms"

    def _render_rendimiento(self, stats: dict, ocultar: bool) -> str:
        """Cuánto tarda y cuánto se ahorra con el caché.

        Los dos números que hay que leer juntos: el caché alto explica por qué
        la navegación se siente rápida, y la latencia de las consultas que sí
        salen a internet es la que avisa cuando algo anda mal con el upstream.
        """
        lat = self.logger_db.latencia(ocultar=ocultar)
        total = stats["total_queries"]
        cache = stats["cached_queries"]
        porcentaje = (cache / total * 100) if total else 0.0

        if not lat["muestras"]:
            detalle = (
                "<p class='empty'>Todavía no salió ninguna consulta a internet, "
                "así que no hay tiempos para promediar.</p>"
            )
        else:
            detalle = (
                "<div class='mini-tarjetas'>"
                f"<div><span class='mini-valor'>{self._ms(lat['promedio'])}</span>"
                "<span class='mini-label'>Promedio a internet (24 h)</span></div>"
                f"<div><span class='mini-valor'>{self._ms(lat['minimo'])}</span>"
                "<span class='mini-label'>La más rápida (24 h)</span></div>"
                f"<div><span class='mini-valor'>{self._ms(lat['maximo'])}</span>"
                "<span class='mini-label'>La más lenta (24 h)</span></div>"
                f"<div><span class='mini-valor'>{self._ms(lat['cache_promedio'])}</span>"
                "<span class='mini-label'>Promedio desde caché (24 h)</span></div>"
                "</div>"
            )

        barra = (
            "<div class='barra-doble'>"
            f"<span class='parte-cache' style='width:{porcentaje:.1f}%'></span>"
            "</div>"
            f"<p class='hint'><strong>{porcentaje:.1f}%</strong> de las consultas se "
            f"respondieron desde el caché ({_miles(cache)} de {_miles(total)}), sin "
            "salir a internet.</p>"
        )

        return (
            "<h3>Rendimiento</h3>"
            "<p class='hint'>El promedio separa las consultas que salen a internet "
            "de las que se responden desde el caché. Mezclarlas daría un número que "
            "baja cuanto más caché tenés y que no sirve para detectar nada: lo que "
            "importa es cuánto tarda una consulta que SÍ tiene que salir, porque si "
            "eso se dispara hay un problema con el upstream o con la red. Los "
            "bloqueos tampoco entran, porque responder un bloqueo es instantáneo.</p>"
            f"{barra}{detalle}"
        )

    def _render_dnssec(self, ocultar: bool) -> str:
        datos = self.logger_db.dnssec(ocultar=ocultar)
        if not datos["total"]:
            return (
                "<h3>DNSSEC</h3>"
                "<p class='empty'>Todavía no hay respuestas para contar.</p>"
            )
        return (
            "<h3>DNSSEC</h3>"
            "<p class='hint'>DNSSEC es la firma criptográfica de una respuesta "
            "DNS: sirve para que nadie en el camino pueda cambiarte a qué IP "
            "resuelve un nombre. <strong>Cuidado con cómo leer este número: "
            "quiere decir que el upstream validó la firma, no que la validamos "
            "nosotros.</strong> Validar de verdad es implementar la cadena de "
            "confianza entera, y este proyecto no escribe criptografía propia. "
            "Lo que se lee es el flag AD que manda Quad9 o Cloudflare.</p>"
            "<div class='barra-doble'>"
            f"<span class='parte-cache' style='width:{datos['porcentaje']:.1f}%'></span>"
            "</div>"
            f"<p class='hint'><strong>{datos['porcentaje']:.1f}%</strong> de las "
            f"respuestas vinieron validadas ({_miles(datos['firmadas'])} de "
            f"{_miles(datos['total'])}). Que el resto no lo esté es normal: buena "
            "parte de internet todavía no firma sus dominios.</p>"
        )

    def _render_geografia(self, ocultar: bool) -> str:
        db = self.logger_db
        paises = db.top_paises(10, ocultar=ocultar)
        proveedores = db.top_proveedores(10, ocultar=ocultar)
        if not paises and not proveedores:
            return (
                "<h3>Adónde apuntan los nombres</h3>"
                "<p class='empty'>No hay datos de geolocalización. Se descargan "
                "una sola vez con <code>python scripts/update_geoip.py</code>, "
                "y después se consultan en disco sin salir a la red.</p>"
            )
        return (
            self._render_barras(
                "Países a los que apuntan los nombres", paises,
                nota="Sale de la IP que devolvió cada respuesta, cruzada contra "
                     "una base local. El resolver ya tenía esa IP en la mano, así "
                     "que no cuesta ninguna consulta extra ni sale a internet.",
            )
            + self._render_barras("Proveedores", proveedores)
        )

    # Ventanas del histórico. La de 12 meses existe aunque al principio no
    # tenga datos: se llena sola con el correr de los días.
    VENTANAS = ((7, "7 días"), (30, "30 días"), (365, "12 meses"))

    def _render_historico(self) -> str:
        dias = 30
        crudo = (getattr(self, "_query_actual", {}) or {}).get("dias")
        if crudo:
            try:
                dias = {7: 7, 30: 30, 365: 365}.get(int(crudo[0]), 30)
            except (TypeError, ValueError):
                dias = 30

        datos = self.logger_db.historico(dias)
        botones = "".join(
            (
                f"<span class='ventana activa'>{etiqueta}</span>"
                if valor == dias else
                f"<a class='ventana' href='/?dias={valor}#stats'>{etiqueta}</a>"
            )
            for valor, etiqueta in self.VENTANAS
        )

        if not datos:
            cuerpo = (
                "<p class='empty'>Todavía no hay días cerrados para resumir. "
                "Cada día que termina se guarda como una fila de resumen.</p>"
            )
        else:
            tope = max(t for _f, t, _b in datos) or 1
            columnas = "".join(
                f"<div class='hcol' title='{html_lib.escape(f)}: {t} consultas, "
                f"{b} bloqueadas'>"
                f"<span class='hbar' style='height:{max(2, int(t / tope * 100))}%'>"
                f"<span class='hbar-bloq' style='height:{int(b / t * 100) if t else 0}%'>"
                "</span></span>"
                f"<span class='hlab'>{html_lib.escape(f[8:])}</span></div>"
                for f, t, b in datos
            )
            cuerpo = f"<div class='horas'>{columnas}</div>"

        return (
            "<h3>Histórico por día</h3>"
            "<p class='hint'>El historial de consultas se recorta cuando pasa el "
            "tope de filas, así que para poder mostrar meses sin guardar meses de "
            "consultas, cada día que termina se resume en una fila aparte que "
            "sobrevive al recorte. Los días en que la máquina estuvo apagada no "
            "aparecen: rellenarlos con ceros haría parecer que el DNS dejó de "
            "funcionar.</p>"
            f"<div class='ventanas'>{botones}</div>{cuerpo}"
        )

    def _render_categorias(self, ocultar: bool) -> str:
        datos = self.logger_db.bloqueos_por_categoria(ocultar=ocultar)
        if not datos:
            return (
                "<h3>De qué se bloqueó</h3>"
                "<p class='empty'>Todavía no se bloqueó ninguna consulta.</p>"
            )
        con_nombre = [(nombre_de_categoria(clave), cuenta) for clave, cuenta in datos]
        return self._render_barras(
            "De qué se bloqueó", con_nombre,
            nota="La categoría no se inventa: sale del feed donde apareció el "
                 "dominio. URLhaus es malware, OpenPhish es phishing, "
                 "StevenBlack es publicidad y rastreadores. Sirve para saber si "
                 "tenés un problema o si simplemente estás filtrando anuncios.",
        )

    def _estado_para_el_puntaje(self) -> dict:
        """Junta lo que el puntaje necesita. Todo ya calculado por otros
        módulos: acá no se decide nada, solo se recolecta."""
        db = self.logger_db
        resolver = self.resolver
        tuneles, anomalias = self._hallazgos()
        # La edad del dominio, si RDAP está activo y ya está en cache. No se
        # sale a la red desde acá: el puntaje se calcula seguido y no puede
        # depender de que un servicio externo conteste.
        for grupo in tuneles:
            dato = None
            if self.rdap is not None:
                dato = self.rdap.edad(grupo["padre"], permitir_red=False)
            grupo["edad_reciente"] = bool(dato and dato["reciente"])
            grupo["edad_dias"] = dato["dias"] if dato else None

        amenazas = {}
        # Con ventana de 24 horas de verdad. Antes esto usaba todo el
        # historial, así que un bloqueo de malware de hace diez días seguía
        # descontando puntos hoy y el puntaje no se recuperaba nunca.
        for categoria, cantidad in db.bloqueos_por_categoria(horas=24):
            if categoria in ("malware", "phishing"):
                amenazas[categoria] = cantidad

        return {
            "modo_upstream": getattr(resolver, "upstream_mode", ""),
            "respaldo_sin_cifrar": bool(getattr(resolver, "dot_fallback_to_udp", True)),
            "tunneling": tuneles,
            "actividad_anomala": anomalias,
            "amenazas_24h": amenazas,
            "horas_desde_feeds": self._horas_desde_feeds(),
            "informativo": {"dnssec": db.dnssec()},
        }

    def _horas_desde_feeds(self) -> float | None:
        """Hace cuánto se actualizaron las listas, en horas. None si nunca."""
        from .config_loader import PROJECT_ROOT

        archivo = PROJECT_ROOT / "data" / "blocklist_feeds.txt"
        try:
            return (time.time() - archivo.stat().st_mtime) / 3600
        except OSError:
            return None

    def _render_resumen(self) -> str:
        """La pestaña que se ve primero: el estado de la red en un vistazo.

        Cada descuento del puntaje es un link a las consultas que lo
        provocaron. Un número que no se puede auditar es un adorno, y uno que
        además tranquiliza sin motivo es peor que no tenerlo.
        """
        estado = self._estado_para_el_puntaje()
        resultado = calcular_puntaje(estado)
        db = self.logger_db
        stats = db.stats(ocultar=self._ocultar_ruido())

        if resultado["descuentos"]:
            lista = "".join(
                "<li><a href='" + html_lib.escape(d["enlace"] or "/") + "'>"
                + html_lib.escape(d["texto"]) + "</a>"
                + f" <span class='resta'>-{d['puntos']}</span></li>"
                for d in resultado["descuentos"]
            )
            detalle = (
                "<p class='hint'>De dónde sale cada punto que se restó. Todos "
                "llevan a las consultas que lo provocaron:</p>"
                f"<ul class='descuentos'>{lista}</ul>"
            )
        else:
            detalle = (
                "<p class='empty'>No se encontró nada que restar: las consultas "
                "van cifradas, no hay hallazgos de comportamiento abiertos, no se "
                "pidió ningún dominio de malware ni de phishing, y las listas "
                "están al día.</p>"
            )

        dnssec = resultado["informativo"].get("dnssec") or {}
        tasa = (
            stats["blocked_queries"] / stats["total_queries"] * 100
            if stats["total_queries"] else 0.0
        )
        tarjetas = "".join(
            f"<div><span class='mini-valor'>{valor}</span>"
            f"<span class='mini-label'>{etiqueta}</span></div>"
            for valor, etiqueta in (
                (_miles(stats["total_queries"]), "Consultas registradas"),
                (f"{tasa:.1f}%", "Se bloquearon"),
                (str(len(estado["tunneling"])), "Posibles túneles abiertos"),
                (str(len(estado["actividad_anomala"])), "Equipos fuera de ritmo"),
                (f"{dnssec.get('porcentaje', 0.0):.0f}%", "Con DNSSEC validado"),
            )
        )

        return (
            f"<div class='puntaje puntaje-{resultado['nivel'].replace('ó', 'o')}'>"
            f"<span class='puntaje-numero'>{resultado['puntaje']}</span>"
            "<span class='puntaje-de'>/100</span>"
            "<span class='puntaje-titulo'>Seguridad del DNS de tu red</span>"
            "</div>"
            "<p class='hint'>Empieza en 100 y baja por hallazgos concretos, "
            "nunca por estimaciones. <strong>No descuenta por cosas que no "
            "controlás</strong>: que buena parte de internet no firme sus "
            "dominios con DNSSEC no es un problema de tu red, así que se muestra "
            "como dato y no como penalización. Y es el puntaje del DNS, no de la "
            "red entera: no sabe nada del tráfico que no pasa por acá.</p>"
            f"{detalle}"
            f"<h3>De un vistazo</h3><div class='mini-tarjetas'>{tarjetas}</div>"
        )

    def _hallazgos(self) -> tuple[list, list]:
        """Los hallazgos de detección, calculados como mucho una vez por minuto.

        El cache está acá, sobre los DATOS, y no sobre el HTML de la pestaña.
        Antes estaba sobre el HTML, y eso dejó un agujero de rendimiento serio:
        la pestaña Resumen y `/api/estado` también necesitan los hallazgos, así
        que los recalculaban por su cuenta en cada refresco, esquivando el
        cache por completo.

        Por qué eso era grave y no solo lento: las detecciones toman el lock
        global de la base durante unos 700 ms sobre 200.000 filas, y
        `log_query` -que está en el camino de CADA consulta DNS- necesita ese
        mismo lock. O sea que cada tick del panel demoraba las consultas de
        toda la red lo mismo. Con doce pestañas abiertas ticando cada cinco
        segundos, el lock quedaba tomado casi todo el tiempo y el DNS empezaba
        a dar timeout: el panel tirando abajo el servicio que mira.

        El cache vive en la clase inyectada de ESTE servidor (`type(self)`) y
        no en la clase base: si viviera en la base, dos resolvers levantados en
        el mismo proceso se mostrarían los hallazgos del otro.

        El lock se sostiene durante el cálculo a propósito: así, si diez
        pestañas piden a la vez con el cache vencido, calcula una y las otras
        nueve esperan ese resultado en vez de lanzar diez cálculos en paralelo.
        """
        propia = type(self)
        with propia._deteccion_lock:
            guardado = propia._deteccion_cache
            if guardado is not None and (time.monotonic() - guardado[0]) < self.TTL_DETECCION:
                return guardado[1]
            tuneles = self.logger_db.tunneling(24)
            # El filtro de "esto ya lo revisé y es normal" se aplica ACÁ y no
            # en la pestaña: si se aplicara al dibujar, el puntaje seguiría
            # restando por un hallazgo que el panel ya no muestra, y tendrías
            # un 75 sin nada visible que lo explique. Un número que no se
            # puede rastrear hasta su causa es exactamente lo que este
            # puntaje promete no ser.
            if self.normales is not None:
                tuneles = self.normales.filtrar(tuneles)
            datos = (tuneles, self.logger_db.actividad_anomala(24))
            propia._deteccion_cache = (time.monotonic(), datos)
            return datos

    def _olvidar_hallazgos(self) -> None:
        """Tira el cache de detección.

        Se llama cuando se marca o se desmarca un hallazgo: sin esto, el
        cambio recién se vería hasta un minuto después y parecería que el
        botón no hizo nada.
        """
        propia = type(self)
        with propia._deteccion_lock:
            propia._deteccion_cache = None

    def _render_deteccion(self) -> str:
        return self._calcular_deteccion()

    def _calcular_deteccion(self) -> str:
        """Lo que solo un resolver puede ver.

        El filtro de ruido no se aplica acá aunque esté prendido: ocultar
        telemetría existe para que se vean las cosas raras, y sería absurdo que
        justamente esconda una detección.
        """
        tuneles, anomalias = self._hallazgos()

        partes = [
            "<p class='hint'>Estas dos detecciones miran la <strong>forma</strong> "
            "del tráfico, no una lista de dominios malos, así que pueden encontrar "
            "cosas que ningún feed conoce. Por lo mismo pueden equivocarse: "
            "<strong>señalan, no bloquean</strong>. Cada hallazgo dice exactamente "
            "por qué se marcó, para que puedas discutirlo en vez de tener que "
            "creerle. Se mira la última 24 horas.</p>"
        ]

        # Tope de consultas RDAP nuevas por vuelta. Como este bloque se
        # recalcula una vez por minuto, en el peor caso son tres pedidos
        # salientes por minuto y no cuarenta de golpe.
        presupuesto = [3]

        def edad_de(dominio: str) -> str:
            rdap = self.rdap
            if rdap is None:
                return ""
            # Primero se mira el cache sin permiso de salir. Solo si no está
            # se gasta presupuesto.
            dato = rdap.edad(dominio, permitir_red=False)
            if dato is None and presupuesto[0] > 0:
                presupuesto[0] -= 1
                dato = rdap.edad(dominio, permitir_red=True)
            if dato is None:
                return ""
            if dato["reciente"]:
                return (
                    f"<p class='aviso-edad'>Dominio registrado hace "
                    f"<strong>{dato['dias']} días</strong> ({dato['fecha']}). "
                    "Los dominios recién registrados son muy usados por malware "
                    "y campañas de phishing, que se queman antes de entrar en "
                    "cualquier lista.</p>"
                )
            return (
                f"<p class='hint'>Dominio registrado hace {dato['dias']} días "
                f"({dato['fecha']}).</p>"
            )

        partes.append("<h3>Posible tunneling por DNS</h3>")
        partes.append(
            "<p class='hint'>Sacar datos de una red por DNS funciona porque el DNS "
            "casi nunca está bloqueado: los datos se codifican en el nombre que se "
            "consulta y la respuesta vuelve en un registro TXT. Se agrupa por equipo "
            "y dominio, y hace falta que coincidan al menos dos señales, porque cada "
            "una por separado tiene explicaciones inocentes.</p>"
        )
        if not tuneles:
            partes.append(
                "<p class='empty'>Nada que marcar. Ningún equipo generó un patrón "
                "de consultas parecido a un túnel en las últimas 24 horas.</p>"
            )
        for grupo in tuneles:
            senales = "".join(
                f"<li>{html_lib.escape(s)}</li>" for s in grupo["senales"]
            )
            partes.append(
                "<div class='hallazgo'>"
                "<div class='hallazgo-head'>"
                f"<span class='hallazgo-titulo'>{html_lib.escape(grupo['padre'])}</span>"
                f"<span class='hallazgo-sub'>desde {html_lib.escape(grupo['cliente'])}</span>"
                "</div>"
                f"<p class='hint'>{_miles(grupo['total'])} consultas, "
                f"{_miles(grupo['distintos'])} nombres distintos.</p>"
                f"{edad_de(grupo['padre'])}"
                f"<ul class='senales'>{senales}</ul>"
                "<div class='acciones-barra acciones-hallazgo'>"
                f"<form method='get' action='/'>"
                f"<input type='hidden' name='q' value='{html_lib.escape(grupo['padre'])}'>"
                "<button type='submit'>Ver las consultas</button></form>"
                f"<form method='get' action='/blockdomain' "
                f"onsubmit=\"return confirmarAccion(this, 'bloquear')\" "
                f"data-dominio='{html_lib.escape(grupo['padre'])}'>"
                f"<input type='hidden' name='domain' value='{html_lib.escape(grupo['padre'])}'>"
                "<button type='submit' class='danger-btn'>Bloquear el dominio</button></form>"
                + (
                    f"<form method='get' action='/normal' "
                    f"onsubmit=\"return confirmarAccion(this, 'normal')\" "
                    f"data-dominio='{html_lib.escape(grupo['padre'])}'>"
                    f"<input type='hidden' name='domain' "
                    f"value='{html_lib.escape(grupo['padre'])}'>"
                    "<button type='submit'>Es normal, no marcarlo más</button></form>"
                    if self.normales is not None else ""
                )
                + "</div></div>"
            )

        partes.append("<h3>Actividad fuera de lo normal</h3>")
        partes.append(
            "<p class='hint'>Cada equipo se compara contra su propia historia y no "
            "contra los demás: una tele consulta muchísimo menos que una notebook, "
            "así que un umbral igual para todos marcaría siempre a la misma máquina. "
            "Se usa la mediana de las horas anteriores, porque con el promedio un "
            "pico previo esconde el siguiente.</p>"
        )
        if not anomalias:
            partes.append(
                "<p class='empty'>Nada que marcar. Ningún equipo se salió de su "
                "ritmo habitual.</p>"
            )
        for hallazgo in anomalias:
            partes.append(
                "<div class='hallazgo'>"
                "<div class='hallazgo-head'>"
                f"<span class='hallazgo-titulo'>{html_lib.escape(hallazgo['cliente'])}</span>"
                f"<span class='hallazgo-sub'>x{hallazgo['factor']:.1f} su ritmo</span>"
                "</div>"
                f"<p class='hint'>{_miles(hallazgo['ultima_hora'])} consultas en la "
                f"última hora, contra {hallazgo['base']:.0f} que es su mediana "
                "habitual.</p>"
                "<div class='acciones-barra acciones-hallazgo'>"
                f"<form method='get' action='/'>"
                f"<input type='hidden' name='cliente' value='{html_lib.escape(hallazgo['cliente'])}'>"
                "<button type='submit'>Ver qué consultó</button></form>"
                "</div></div>"
            )

        partes.append(self._render_normales())
        return "".join(partes)

    def _render_normales(self) -> str:
        """Lo que se está silenciando, y el botón para dejar de silenciarlo.

        Va siempre visible, incluso vacío. Un panel que oculta hallazgos sin
        decir cuáles termina en verde por acumulación de decisiones que nadie
        recuerda haber tomado, que es la peor forma de estar tranquilo.
        """
        normales = self.normales
        if normales is None:
            return ""
        marcados = normales.marcados()
        partes = [
            "<h3>Marcados como normales</h3>",
            "<p class='hint'>Patrones que ya revisaste y son esperables en tu red. "
            "No aparecen arriba y no restan puntaje. <strong>No es una lista "
            "blanca</strong>: estos dominios se siguen filtrando y registrando "
            "igual que cualquier otro, y sus consultas se ven enteras en el "
            "historial.</p>",
        ]
        if not marcados:
            partes.append(
                "<p class='empty'>Ninguno. Cuando un hallazgo tenga una "
                "explicación (un CDN de video, por ejemplo), marcalo desde su "
                "botón y va a quedar listado acá.</p>"
            )
            return "".join(partes)
        filas = "".join(
            "<tr>"
            f"<td>{html_lib.escape(d)}</td>"
            "<td><a class='muted' href=\"/vigilar?domain="
            f"{quote(d)}\">Volver a vigilar</a></td>"
            "</tr>"
            for d in marcados
        )
        partes.append(f"<table><tbody>{filas}</tbody></table>")
        return "".join(partes)

    def _render_estadisticas(self, ocultar: bool) -> str:
        db = self.logger_db
        por_hora = db.por_hora(24, ocultar=ocultar)
        grafico = self._render_por_hora(por_hora)
        top = self._render_barras(
            "Top 10 de nombres consultados",
            db.top_dominios(10, ocultar=ocultar),
        )
        top_bloq = self._render_barras(
            "Top 10 de nombres bloqueados",
            db.top_dominios(10, solo_bloqueadas=True, ocultar=ocultar),
        )
        clientes = db.top_clientes(10, ocultar=ocultar)
        clientes_html = self._render_barras(
            "Quién consulta más",
            [(ip, total) for ip, total, _bloq in clientes],
            nota="Cada equipo de la red que le pregunta a este resolver. Es lo "
                 "que un DNS puede decir y un proxy de una sola máquina no.",
        )
        peligrosos = db.top_clientes(10, ocultar=ocultar, ordenar_por="bloqueadas")
        peligrosos = [(ip, bloq) for ip, _total, bloq in peligrosos if bloq]
        peligrosos_html = self._render_barras(
            "Equipos con más bloqueos", peligrosos,
            nota="Es otra pregunta distinta de la de arriba. El que más consulta "
                 "suele ser simplemente el que más se usa; el que más bloqueos "
                 "junta es el que hay que ir a mirar.",
        )
        tipos = self._render_barras(
            "Tipos de consulta",
            db.tipos_de_consulta(8, ocultar=ocultar),
            nota="A y AAAA son lo normal. Una proporción alta de TXT o NULL es "
                 "la firma más visible del tunneling por DNS, porque son los "
                 "tipos que dejan meter datos arbitrarios en la respuesta.",
        )
        motivos = self._render_barras(
            "Por qué se bloqueó", db.bloqueos_por_motivo(10, ocultar=ocultar),
        )
        return (
            grafico
            + self._render_historico()
            + self._render_rendimiento(self.logger_db.stats(ocultar=ocultar), ocultar)
            + self._render_dnssec(ocultar)
            + self._render_categorias(ocultar)
            + top + top_bloq + clientes_html + peligrosos_html + tipos + motivos
            + self._render_geografia(ocultar)
        )

    @staticmethod
    def _render_por_hora(datos: list[tuple[str, int, int]]) -> str:
        if not datos:
            return (
                "<h3>Últimas 24 horas</h3>"
                "<p class='empty'>Todavía no hay consultas registradas.</p>"
            )
        tope = max(total for _, total, _ in datos) or 1
        columnas = "".join(
            f"<div class='hcol' title='{html_lib.escape(hora_local(h))}: {total} consultas, "
            f"{bloq} bloqueadas'>"
            f"<span class='hbar' style='height:{max(2, int(total / tope * 100))}%'>"
            f"<span class='hbar-bloq' style='height:{int(bloq / total * 100) if total else 0}%'>"
            "</span></span>"
            f"<span class='hlab'>{html_lib.escape(hora_local(h))}</span></div>"
            for h, total, bloq in datos
        )
        return (
            "<h3>Últimas 24 horas</h3>"
            "<p class='hint'>Cada barra es una hora, en tu hora local. La parte "
            "roja de arriba es lo que se bloqueó.</p>"
            f"<div class='horas'>{columnas}</div>"
        )

    def _filtros_actuales(self) -> dict:
        """Los filtros finos que vienen por la URL.

        Van por la URL y no por una sesión para que un filtro puesto sea un
        link que se puede compartir o guardar. El "Ver las consultas" de la
        pestaña Detección es justamente eso.
        """
        crudos = getattr(self, "_query_actual", {}) or {}
        return {
            "qtype": (crudos.get("tipo") or [""])[0].strip(),
            "categoria": (crudos.get("cat") or [""])[0].strip(),
            "cliente": (crudos.get("cliente") or [""])[0].strip(),
        }

    def _render_buscador(self, consulta: str, encontradas: int) -> str:
        filtros = self._filtros_actuales()
        hay_filtros = any(filtros.values())

        if consulta or hay_filtros:
            partes = []
            if consulta:
                partes.append(f"coinciden con <strong>{html_lib.escape(consulta)}</strong>")
            if filtros["qtype"]:
                partes.append(f"de tipo <strong>{html_lib.escape(filtros['qtype'])}</strong>")
            if filtros["categoria"]:
                partes.append(
                    "de categoría <strong>"
                    f"{html_lib.escape(nombre_de_categoria(filtros['categoria']))}</strong>"
                )
            if filtros["cliente"]:
                partes.append(f"del equipo <strong>{html_lib.escape(filtros['cliente'])}</strong>")
            resumen = (
                f"<p class='hint'>{encontradas} consultas {' y '.join(partes)}. "
                "<a href='/'>Limpiar y ver solo los últimos bloqueos</a></p>"
            )
        else:
            resumen = (
                "<p class='hint'>Se muestran los últimos bloqueos. Buscá por "
                "nombre o por IP del equipo para auditar todo el historial, o "
                "usá los filtros para acotarlo.</p>"
            )

        def opciones(nombre: str, actual: str, valores: list[tuple[str, str]]) -> str:
            # Escapado, como todo el resto del panel. Los valores vienen de la
            # base (tipos de consulta y categorías), o sea que su origen último
            # es la red: hoy ninguno de los dos caminos deja meter HTML, pero
            # este era el único lugar del panel donde un dato de la base salía
            # crudo, y "hoy no se puede" es exactamente la clase de suposición
            # que deja de valer cuando se agrega un feed nuevo.
            partes = [f"<select name='{html_lib.escape(nombre)}'>"]
            for valor, etiqueta in valores:
                marca = " selected" if valor == actual else ""
                partes.append(
                    f"<option value='{html_lib.escape(str(valor))}'{marca}>"
                    f"{html_lib.escape(str(etiqueta))}</option>"
                )
            partes.append("</select>")
            return "".join(partes)

        # Los valores salen de lo que REALMENTE hay en la base y no de una
        # lista fija: ofrecer un filtro por "NULL" cuando nunca llegó una
        # consulta NULL es prometer algo que va a devolver cero.
        tipos = [("", "cualquier tipo")] + [
            (t, t) for t, _c in self.logger_db.tipos_de_consulta(12) if t
        ]
        categorias = [("", "cualquier categoría")] + [
            (c, nombre_de_categoria(c))
            for c, _n in self.logger_db.bloqueos_por_categoria()
        ]

        return (
            "<form class='add-form buscador' method='get' action='/'>"
            f"<input type='text' name='q' placeholder='buscar por nombre o IP...' "
            f"value='{html_lib.escape(consulta)}'>"
            + opciones("tipo", filtros["qtype"], tipos)
            + opciones("cat", filtros["categoria"], categorias)
            + f"<input type='text' name='cliente' placeholder='equipo (IP)' "
              f"value='{html_lib.escape(filtros['cliente'])}'>"
            + "<button type='submit'>Buscar</button></form>" + resumen
        )

    @staticmethod
    def _render_editable_list(items: list[str], remove_endpoint: str, vacio: str = "") -> str:
        if not items:
            return f"<p class='empty'>{vacio or 'No hay dominios cargados todavía.'}</p>"
        rows = "".join(
            f"<tr><td>{html_lib.escape(domain)}</td>"
            f"<td><a class='danger' href=\"{remove_endpoint}?domain={quote(domain)}\" "
            f"data-dominio='{html_lib.escape(domain)}' "
            f"onclick=\"return confirmarAccion(this, 'quitar')\">Quitar</a></td></tr>"
            for domain in items
        )
        return f"<table><tr><th>Dominio</th><th>Acción</th></tr>{rows}</table>"

    def _render_niveles(self) -> str:
        actual = self._nivel_actual()
        tarjetas = []
        for nombre, nivel in self.NIVELES.items():
            activo = nombre == actual
            clase = "optcard activa" if activo else "optcard"
            if activo:
                accion = "<span class='badge-activo'>&#10003; en uso</span>"
            else:
                accion = (
                    f"<form method='get' action='/nivel' "
                    f"onsubmit=\"return confirm('¿Pasar al nivel "
                    f"{nivel['etiqueta']}?')\">"
                    f"<input type='hidden' name='v' value='{nombre}'>"
                    f"<button type='submit'>Poner este nivel</button></form>"
                )
            tarjetas.append(
                f"<div class='{clase}'><div class='optcard-head'>"
                f"<span class='optcard-title'>{nivel['etiqueta']}</span></div>"
                f"<p class='hint'>{nivel['resumen']}</p>{accion}</div>"
            )
        aviso = ""
        if actual == "personalizado":
            aviso = (
                "<p class='hint'>Ahora mismo la configuración es "
                "<strong>personalizada</strong>: tocaste alguna opción suelta y "
                "ya no coincide con ninguno de los tres niveles. No tiene nada "
                "de malo; se dice para que no quede un nivel marcado que no es "
                "el que está puesto.</p>"
            )
        return (
            "<h2>Nivel de seguridad</h2>"
            "<p class='hint'>Un atajo para fijar varias opciones de una. "
            "Cada nivel se puede seguir ajustando a mano abajo.</p>"
            f"{aviso}<div class='opciones'>{''.join(tarjetas)}</div>"
        )

    def _render_config_panel(self) -> str:
        resolver = self.resolver
        modo = getattr(resolver, "upstream_mode", "dot")
        fallback = bool(getattr(resolver, "dot_fallback_to_udp", True))
        ttl = getattr(resolver, "min_cache_ttl", 30)
        ads = bool(self._valores_actuales()["enable_ad_tracker_blocklist"])
        ocultar = self._ocultar_ruido()

        def tarjeta_modo(valor: str, etiqueta: str, subtitulo: str,
                         descripcion: str, confirmacion: str) -> str:
            activo = modo == valor
            clase = "optcard activa" if activo else "optcard"
            if activo:
                accion = "<span class='badge-activo'>&#10003; en uso</span>"
            else:
                accion = (
                    f"<form method='get' action='/config' "
                    f"onsubmit=\"return confirm('{confirmacion}')\">"
                    f"<input type='hidden' name='k' value='upstream_mode'>"
                    f"<input type='hidden' name='v' value='{valor}'>"
                    f"<button type='submit'>Cambiar a este modo</button></form>"
                )
            return (
                f"<div class='{clase}'>"
                f"<div class='optcard-head'><span class='optcard-title'>{etiqueta}</span>"
                f"<span class='optcard-sub'>{subtitulo}</span></div>"
                f"<p class='hint'>{descripcion}</p>{accion}</div>"
            )

        modo_bloqueo = getattr(self.resolver, "block_mode", "nxdomain")

        def tarjeta_bloqueo(valor: str, etiqueta: str, subtitulo: str,
                            descripcion: str) -> str:
            activo = modo_bloqueo == valor
            clase = "optcard activa" if activo else "optcard"
            if activo:
                accion = "<span class='badge-activo'>&#10003; en uso</span>"
            else:
                accion = (
                    "<form method='get' action='/config'>"
                    "<input type='hidden' name='k' value='block_mode'>"
                    f"<input type='hidden' name='v' value='{valor}'>"
                    "<button type='submit'>Usar este modo</button></form>"
                )
            return (
                f"<div class='{clase}'>"
                f"<div class='optcard-head'><span class='optcard-title'>{etiqueta}</span>"
                f"<span class='optcard-sub'>{subtitulo}</span></div>"
                f"<p class='hint'>{descripcion}</p>{accion}</div>"
            )

        def interruptor(clave: str, encendido: bool, texto_prender: str,
                        texto_apagar: str, confirmacion: str = "") -> str:
            nuevo = "0" if encendido else "1"
            texto = texto_apagar if encendido else texto_prender
            clase = "danger-btn" if encendido else "ok-btn"
            pill = "pill on" if encendido else "pill off"
            estado = "activado" if encendido else "desactivado"
            confirm = f" onsubmit=\"return confirm('{confirmacion}')\"" if confirmacion else ""
            return (
                f"<div class='fila-switch'>"
                f"<form method='get' action='/config'{confirm}>"
                f"<input type='hidden' name='k' value='{clave}'>"
                f"<input type='hidden' name='v' value='{nuevo}'>"
                f"<button class='{clase}' type='submit'>{texto}</button></form>"
                f"<span class='leyenda'>actualmente <span class='{pill}'>{estado}</span></span>"
                f"</div>"
            )

        aviso_udp = (
            "En modo UDP tus consultas DNS viajan en TEXTO PLANO: tu proveedor "
            "de internet puede ver qué dominios consultás. Usalo solo si tu red "
            "bloquea el cifrado. ¿Cambiar a texto plano?"
        )
        aviso_dot = "¿Volver a DNS-over-TLS? Las consultas vuelven a viajar cifradas."
        aviso_fallback = (
            "¿Exigir cifrado siempre? Si algún día tu red bloquea el puerto 853, "
            "no vas a poder resolver nombres (internet parecerá caído)."
            if fallback else
            "¿Permitir el respaldo en texto plano cuando el cifrado no esté disponible?"
        )
        aviso_ads = (
            "¿Desactivar el bloqueo de publicidad y rastreadores? Requiere reiniciar el resolver."
            if ads else
            "¿Activar el bloqueo de publicidad y rastreadores? Requiere reiniciar el "
            "resolver para descargar la lista. Alguna página podría verse distinta."
        )
        aviso_ruido = (
            "¿Volver a mostrar la telemetría en el panel?"
            if ocultar else
            "¿Ocultar del panel la telemetría y las comprobaciones de conexión? "
            "Se siguen resolviendo y registrando igual: solo dejan de aparecer."
        )

        cuantos_ruidosos = self.vista.cantidad_de_dominios if self.vista else 0
        lista_ruido = self._render_editable_list(
            self.vista.dominios_manuales() if self.vista else [],
            "/mostrar",
            vacio="La lista está vacía.",
        )

        return f"""
    {self._render_niveles()}

    <h2>Transporte hacia los servidores upstream</h2>
    <p class="hint">Se aplica al instante, sin reiniciar.</p>
    <div class="opciones">
      {tarjeta_modo("dot", "DNS-over-TLS", "cifrado · recomendado",
                    "Las consultas viajan cifradas por el puerto 853: tu proveedor de internet no puede leer qué dominios consultás, y el certificado del servidor se valida para que nadie pueda hacerse pasar por él.",
                    aviso_dot)}
      {tarjeta_modo("udp", "UDP en texto plano", "clásico · sin cifrar",
                    "El modo tradicional por el puerto 53. Más compatible con redes que bloquean el 853, pero cualquiera en el camino puede ver qué dominios consultás.",
                    aviso_udp)}
    </div>

    <h2>Si el cifrado no está disponible</h2>
    <p class="hint">Cuando ningún servidor responde por TLS (redes que bloquean
    el puerto 853), ¿se permite consultar en texto plano? Activado prioriza que
    internet siga funcionando; desactivado prioriza privacidad estricta: sin
    cifrado, no se resuelve. Se aplica al instante.</p>
    {interruptor("dot_fallback_to_udp", fallback, "Permitir respaldo en texto plano", "Exigir cifrado siempre", aviso_fallback)}

    <h2>Bloqueo de publicidad y rastreadores</h2>
    <p class="hint">Categoría aparte de las amenazas: suma un feed de dominios
    de publicidad y tracking. Está separado a propósito, porque bloquear ads no
    es lo mismo que bloquear malware (alguna página puede depender de un
    tracker para verse bien). <strong>Requiere reiniciar el resolver</strong>
    para descargar y cargar la lista.</p>
    {interruptor("enable_ad_tracker_blocklist", ads, "Activar", "Desactivar", aviso_ads)}

    <h2>Ocultar telemetría y comprobaciones del panel</h2>
    <p class="hint">Un resolver ve TODO lo que pregunta la red, y buena parte
    es ruido previsible: comprobaciones de conexión, actualizaciones,
    verificación de certificados. Con eso, el Top 10 son diez dominios de
    telemetría y no se ve si apareció algo raro. Esto los saca de la VISTA:
    <strong>no cambia nada de lo que se bloquea</strong>, no se borra ni un
    dato, el panel siempre dice cuántas consultas ocultó, y el buscador las
    encuentra igual. Se aplica al instante.</p>
    {interruptor("hide_noise", ocultar, "Ocultar la telemetría", "Volver a mostrarla", aviso_ruido)}

    <h3>Dominios que se están ocultando</h3>
    <p class="hint">La lista que viene de fábrica cubre el ruido de sistema
    (Windows, certificados, reloj, comprobaciones de internet). El ruido de tus
    aplicaciones -Docker, Steam, lo que tengas abierto todo el día- lo sumás
    acá, o de un clic desde el botón <strong>Ocultar</strong> del historial.
    También podés sacar cualquiera de los que vienen puestos.</p>
    <form class="add-form" method="get" action="/ocultar">
      <input type="text" name="domain" placeholder="desktop.docker.com" required>
      <button type="submit">Ocultar del panel</button>
    </form>
    <details class="plegable">
      <summary>Ver los {cuantos_ruidosos} dominios ocultos</summary>
      {lista_ruido}
    </details>

    <h2>Con qué se responde un dominio bloqueado</h2>
    <p class="hint">No es una preferencia estética: cambia cómo se comporta la
    aplicación que consultó. Para tipos que no son A ni AAAA (TXT, MX...)
    siempre se responde NXDOMAIN en cualquier modo, porque fabricar una
    respuesta inventada sería peor que decir que el nombre no existe. Se aplica
    al instante.</p>
    <div class="opciones">
      {tarjeta_bloqueo("nxdomain", "NXDOMAIN", "el nombre no existe",
                       "Lo más limpio conceptualmente: es lo mismo que responde un resolver cuando el nombre realmente no existe. El problema es que algunas aplicaciones lo leen como «se cayó la red» y arrancan a reintentar, o muestran un cartel de sin conexión.")}
      {tarjeta_bloqueo("zero", "0.0.0.0", "no va a ninguna parte",
                       "El nombre existe pero apunta a la nada, así que la conexión falla al instante y sin reintentos de DNS. Es el modo que usa Pi-hole por defecto y suele romper menos cosas.")}
      {tarjeta_bloqueo("localhost", "127.0.0.1", "se queda en tu máquina",
                       "Igual que el anterior, pero el intento de conexión se queda en la propia máquina. Sirve si tenés algo escuchando ahí que muestre una página de «esto está bloqueado».")}
    </div>

    <h2>Caché mínimo de respuestas</h2>
    <p class="hint">Segundos que se guarda una respuesta como mínimo, aunque su
    propio TTL sea menor. Más alto = menos consultas salientes y más velocidad;
    más bajo = cambios de DNS se reflejan antes. Se aplica al instante.</p>
    <form class="add-form" method="get" action="/config">
      <input type="hidden" name="k" value="min_cache_ttl">
      <input type="number" name="v" min="0" max="86400" value="{ttl}" required>
      <button type="submit">Guardar</button>
    </form>
    <p class="hint">Actual: <strong>{ttl}</strong> segundos (default: 30)</p>

    <h2>Borrar el historial</h2>
    <p class="hint">Vacía la base de consultas y compacta el archivo. El
    historial se recorta solo cuando pasa el tope de filas, así que esto es
    para cuando querés empezar de cero, no mantenimiento.</p>
    <form method="get" action="/borrar-historial" onsubmit="return confirm('¿Borrar TODO el historial de consultas? No se puede deshacer.')">
      <button type="submit" class="danger-btn">Borrar el historial entero</button>
    </form>

    <h2>Lo que se cambia desde el archivo</h2>
    <p class="hint">Necesitan reiniciar y viven en <code>config/config.yaml</code>:
    los servidores upstream (hoy Quad9 y Cloudflare) con sus nombres de
    certificado, el puerto donde escucha el resolver, el del dashboard, cada
    cuánto se refrescan los feeds de amenazas y el tope de filas del
    historial.</p>
"""

    # ---------- la página ----------

    def _serve_dashboard(self) -> None:
        consulta = (self._query_actual.get("q") or [""])[0].strip()
        frag = self._fragmentos(consulta)
        tarjetas_html = frag["tarjetas"]
        historial_html = frag["historial"]
        estadisticas_html = frag["estadisticas"]
        deteccion_html = frag["deteccion"]
        resumen_html = frag["resumen"]
        ruido_html = frag["ruido"]

        aviso = (self._query_actual.get("aviso") or [""])[0].strip()
        aviso_html = (
            f"<p class='aviso-accion'>{html_lib.escape(aviso)}</p>" if aviso else ""
        )

        buscador = self._render_buscador(consulta, frag["encontradas"])
        allowlist_html = self._render_editable_list(self.allowlist.manual_entries(), "/unallow")
        blocklist_html = self._render_editable_list(self.blocklist.manual_entries(), "/unblockdomain")
        config_html = self._render_config_panel()

        if callable(type(self).apagar):
            apagar_html = (
                "<form method=\"get\" action=\"/apagar\" "
                "onsubmit=\"return confirmarApagado()\">"
                "<button type=\"submit\" class=\"apagar-btn\">Apagar resolver</button>"
                "</form>"
            )
        else:
            apagar_html = ""

        page = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>SecureDNS - Dashboard</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, "Segoe UI", sans-serif; background:#0f1115; color:#e6e6e6; padding:2rem; max-width: 960px; margin: 0 auto; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.1rem; margin-top:1.6rem; margin-bottom:0.3rem; }}
  h3 {{ font-size: 0.98rem; margin:1.4rem 0 0.4rem; }}
  .subtitle {{ color:#9aa0a6; font-size:0.85rem; margin-top:0; }}
  .stats {{ display:flex; gap:1.25rem; margin: 1.5rem 0; flex-wrap: wrap; align-items: stretch; }}
  .card {{ background:#1a1d24; border-radius:8px; padding:1rem 1.5rem; min-width:140px; }}
  .card .value {{ font-size:1.8rem; font-weight:600; }}
  .card .label {{ color:#9aa0a6; font-size:0.85rem; }}
  table {{ width:100%; border-collapse: collapse; margin-top:0.5rem; }}
  th, td {{ text-align:left; padding:0.5rem 0.75rem; border-bottom:1px solid #2a2e37; font-size:0.85rem; }}
  th {{ color:#9aa0a6; font-weight:500; }}
  .empty {{ color:#9aa0a6; font-size:0.85rem; }}
  .hint {{ color:#9aa0a6; font-size:0.82rem; line-height:1.5; }}
  code {{ background:#1a1d24; padding:0.1rem 0.35rem; border-radius:4px; }}
  .opciones {{ display:flex; gap:0.9rem; flex-wrap:wrap; margin:0.9rem 0 0.4rem; }}
  .optcard {{ flex:1 1 260px; background:#161922; border:1px solid #2a2e37; border-radius:10px; padding:0.9rem 1rem; }}
  .optcard.activa {{ border-color:#3f7d52; background:#16241a; }}
  .optcard-head {{ display:flex; align-items:baseline; gap:0.5rem; flex-wrap:wrap; margin-bottom:0.35rem; }}
  .optcard-title {{ font-size:1rem; font-weight:600; }}
  .optcard-sub {{ font-size:0.75rem; color:#9aa0a6; text-transform:uppercase; letter-spacing:0.04em; }}
  .optcard .hint {{ margin:0 0 0.7rem; }}
  .optcard button {{ width:100%; }}
  .badge-activo {{ display:inline-block; background:#1e3a26; color:#7bd88f; border-radius:6px; padding:0.4rem 0.8rem; font-size:0.85rem; }}
  .fila-switch {{ display:flex; align-items:center; gap:0.75rem; margin:0.6rem 0 0.2rem; flex-wrap:wrap; }}
  .pill {{ display:inline-block; border-radius:999px; padding:0.25rem 0.75rem; font-size:0.78rem; font-weight:600; }}
  .pill.on {{ background:#1e3a26; color:#7bd88f; }}
  .pill.off {{ background:#24262e; color:#9aa0a6; }}
  .pill.off-red {{ background:#3a1f22; color:#ff8a8a; }}
  .leyenda {{ color:#9aa0a6; font-size:0.85rem; }}
  button {{ background:#2a2e37; border:none; color:#e6e6e6; border-radius:6px; padding:0.5rem 1rem; cursor:pointer; font-size:0.85rem; font-family:inherit; transition:filter 0.15s ease; }}
  button:hover {{ filter:brightness(1.25); }}
  button.ok-btn {{ background:#1e3a26; color:#7bd88f; }}
  button.danger-btn {{ background:#3a1f22; color:#ff8a8a; }}
  /* Apagar no es "una acción destructiva más": deja la red sin resolver
     nombres. Va con borde para que se distinga de Borrar cache. */
  button.apagar-btn {{ background:#2b1416; color:#ff7b72; border:1px solid #6b2a2a; }}
  a {{ color:#7fb2ff; }}
  a.danger {{ color:#ff8a8a; }}
  a.muted {{ color:#9aa0a6; }}
  /* Las acciones de cada fila del historial hacen cosas distintas, y en azul
     las tres parecían tres formas de lo mismo. El color es un semáforo, y
     coincide con el que ya usan los botones y las pastillas de estado:
       verde    (#7bd88f, el de ok-btn) = dejar pasar. Permitir.
       rojo     (#ff8a8a, el de danger) = cortar. Bloquear. Es el mismo rojo
                de la pastilla "bloqueada", así que la fila entera se lee
                igual: rojo es tráfico que no pasa.
       amarillo (#e3b341)               = Ocultar. Ni deja pasar ni corta:
                cambia lo que ves y nada más. El amarillo dice justamente
                "esto no es una decisión de seguridad", que es lo que hay que
                entender de este botón.
       azul     (el default)            = Detalle. No cambia nada. */
  a.accion-permitir {{ color:#7bd88f; }}
  a.accion-bloquear {{ color:#ff8a8a; }}
  a.accion-ocultar {{ color:#e3b341; }}
  .acciones-barra {{ display:flex; gap:0.5rem; justify-content:flex-end; margin:-0.5rem 0 0.5rem; flex-wrap:wrap; }}
  .acciones-barra form {{ margin:0; }}
  .tabs {{ display:flex; gap:0.5rem; margin-top:1.5rem; border-bottom:1px solid #2a2e37; flex-wrap:wrap; }}
  /* border-radius:0 explícito: las pestañas son <button> y heredaban el
     redondeo de la regla general, lo que curvaba las puntas de la línea
     azul del subrayado. Acá la línea tiene que ser recta. */
  .tab-btn {{ background:none; border:none; border-radius:0; color:#9aa0a6; font-size:0.9rem; font-family:inherit; padding:0.6rem 1rem; cursor:pointer; border-bottom:2px solid transparent; }}
  .tab-btn.active {{ color:#e6e6e6; border-bottom:2px solid #7fb2ff; }}
  .tab-panel {{ display:none; padding-top:1rem; }}
  .tab-panel.active {{ display:block; }}
  .add-form {{ display:flex; gap:0.5rem; margin-bottom:1rem; }}
  .add-form input[type=text] {{ flex:1; background:#1a1d24; border:1px solid #2a2e37; color:#e6e6e6; border-radius:6px; padding:0.5rem 0.75rem; }}
  .add-form select {{ background:#1a1d24; border:1px solid #2a2e37; color:#e6e6e6; border-radius:6px; padding:0.5rem 0.6rem; font-family:inherit; font-size:0.85rem; }}
  .buscador {{ flex-wrap:wrap; }}
  .buscador input[type=text] {{ min-width:12rem; }}
  .add-form input[type=number] {{ background:#1a1d24; border:1px solid #2a2e37; color:#e6e6e6; border-radius:6px; padding:0.5rem 0.75rem; width:110px; }}
  .aviso-accion {{ background:#132a1c; border:1px solid #1e4630; color:#a7e0bd; border-radius:8px; padding:0.7rem 0.9rem; margin:0 0 1rem 0; font-size:0.9rem; }}
  .aviso-ruido {{ background:#1a1d24; border:1px solid #2a2e37; color:#9aa0a6; border-radius:8px; padding:0.6rem 0.9rem; margin:0 0 1rem; font-size:0.84rem; line-height:1.5; }}
  /* Los 50 dominios de telemetría se pliegan: son una lista larga que casi
     nunca se mira, y desplegada tapa el resto de la configuración. */
  /* Detalle de una consulta: fila oculta que se despliega desde "Detalle". */
  tr.detalle {{ display:none; }}
  tr.detalle.abierta {{ display:table-row; }}
  tr.detalle > td {{ background:#12151c; padding:0.4rem 0.6rem; }}
  /* El detalle es una TARJETA, no unas líneas sueltas debajo de la fila.
     Con el borde y el fondo propio se lee como "esto es lo que sabemos de
     esta consulta" y no como una continuación de la tabla, que era el
     problema: se confundía con la fila siguiente. Es el mismo formato que el
     detalle de SecureProxy, para que los tres paneles se lean igual. */
  .detalle-caja {{ display:flex; flex-direction:column; background:#161922;
                   border:1px solid #2a2e37; border-radius:10px;
                   padding:0.9rem 1.1rem; margin:0.3rem 0; }}
  .detalle-fila {{ display:flex; gap:0.75rem; font-size:0.86rem;
                   align-items:baseline; padding:0.28rem 0; flex-wrap:wrap; }}
  .detalle-fila + .detalle-fila {{ border-top:1px solid #1d2029; }}
  .detalle-clave {{ width:15rem; min-width:15rem; color:#9aa0a6; }}
  /* Monoespaciada: la mitad de estos valores son direcciones, puertos y
     tiempos, y en una fuente proporcional cuesta compararlos entre filas. */
  .detalle-valor {{ color:#e6e6e6; word-break:break-all;
                    font-family:Consolas,"Courier New",monospace; }}
  .detalle-valor.malo {{ color:#ff8a8a; }}
  .detalle-valor.bueno {{ color:#7bd88f; }}
  /* Tarjetitas de rendimiento, más chicas que las de arriba de todo. */
  .mini-tarjetas {{ display:flex; gap:1rem; flex-wrap:wrap; margin:0.6rem 0 0.4rem; }}
  .mini-tarjetas > div {{ background:#161922; border:1px solid #2a2e37; border-radius:8px;
                          padding:0.6rem 0.9rem; min-width:11rem; }}
  .mini-valor {{ display:block; font-size:1.3rem; font-weight:600; }}
  .mini-label {{ display:block; color:#9aa0a6; font-size:0.78rem; margin-top:0.15rem; }}
  /* Barra de caché contra internet. */
  .barra-doble {{ background:#3d5a80; border-radius:4px; height:0.85rem;
                  overflow:hidden; margin:0.5rem 0 0.3rem; }}
  .parte-cache {{ display:block; height:100%; background:#3f7d52; }}
  /* Hallazgos de la pestaña Detección. Borde ámbar y no rojo a propósito:
     esto señala algo para mirar, no confirma que sea malo. */
  .hallazgo {{ background:#1a1710; border:1px solid #4a3a1a; border-left:3px solid #d9a441;
               border-radius:10px; padding:0.9rem 1.1rem; margin:0.8rem 0; }}
  .hallazgo-head {{ display:flex; align-items:baseline; gap:0.6rem; flex-wrap:wrap;
                    margin-bottom:0.3rem; }}
  .hallazgo-titulo {{ font-size:1rem; font-weight:600; color:#f0c674; word-break:break-all; }}
  .hallazgo-sub {{ font-size:0.78rem; color:#9aa0a6; text-transform:uppercase;
                   letter-spacing:0.04em; }}
  .senales {{ margin:0.5rem 0 0.7rem; padding-left:1.1rem; color:#c9d1d9;
              font-size:0.84rem; line-height:1.6; }}
  /* El puntaje. El color acompaña al número: verde tranquiliza, ámbar pide
     una mirada, rojo pide acción. */
  .puntaje {{ display:flex; align-items:baseline; gap:0.5rem; flex-wrap:wrap;
              border-radius:12px; padding:1.2rem 1.5rem; margin:0.5rem 0 1rem;
              border:1px solid #2a2e37; background:#161922; }}
  .puntaje-bien {{ border-color:#3f7d52; background:#16241a; }}
  .puntaje-atencion {{ border-color:#6b5320; background:#1f1b10; }}
  .puntaje-mal {{ border-color:#6b2a2a; background:#201416; }}
  .puntaje-numero {{ font-size:3.2rem; font-weight:700; line-height:1; }}
  .puntaje-de {{ font-size:1.1rem; color:#9aa0a6; }}
  .puntaje-titulo {{ margin-left:auto; color:#c9d1d9; font-size:0.95rem; }}
  .descuentos {{ margin:0.5rem 0 1rem; padding-left:1.1rem; font-size:0.86rem;
                 line-height:1.8; }}
  .descuentos a {{ color:#e6e6e6; }}
  .resta {{ color:#ff8a8a; font-weight:600; margin-left:0.3rem; }}
  .aviso-edad {{ background:#2b1416; border:1px solid #6b2a2a; color:#ffb3ae;
                 border-radius:8px; padding:0.5rem 0.8rem; margin:0.5rem 0;
                 font-size:0.84rem; line-height:1.5; }}
  .acciones-hallazgo {{ justify-content:flex-start; margin:0; }}
  .plegable {{ margin:0.6rem 0 1rem 0; }}
  .plegable > summary {{ cursor:pointer; color:#7fb2ff; font-size:0.9rem;
                         padding:0.3rem 0; user-select:none; }}
  /* Barras horizontales de las estadísticas. */
  .barras {{ display:flex; flex-direction:column; gap:0.3rem; margin:0.4rem 0 0.8rem; }}
  .barra-fila {{ display:flex; align-items:center; gap:0.6rem; font-size:0.82rem; }}
  .barra-nombre {{ width:16rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#c9d1d9; }}
  .barra {{ flex:1; background:#1a1d24; border-radius:4px; height:0.85rem; overflow:hidden; }}
  .barra-relleno {{ display:block; height:100%; background:#3d5a80; }}
  .barra-valor {{ width:4rem; text-align:right; color:#9aa0a6; }}
  /* Gráfico de las últimas 24 horas. */
  .horas {{ display:flex; align-items:flex-end; gap:0.25rem; height:9rem; margin:0.6rem 0 0.4rem; }}
  .hcol {{ flex:1; display:flex; flex-direction:column; justify-content:flex-end; align-items:center; height:100%; }}
  .hbar {{ width:100%; background:#3d5a80; border-radius:3px 3px 0 0; display:flex; flex-direction:column; justify-content:flex-start; }}
  .hbar-bloq {{ width:100%; background:#8a3d42; border-radius:3px 3px 0 0; }}
  .hlab {{ font-size:0.65rem; color:#9aa0a6; margin-top:0.25rem; }}
  .ventanas {{ display:flex; gap:0.4rem; margin:0.6rem 0 0.2rem; flex-wrap:wrap; }}
  .ventana {{ border:1px solid #2a2e37; border-radius:999px; padding:0.25rem 0.8rem;
              font-size:0.8rem; color:#9aa0a6; text-decoration:none; }}
  .ventana.activa {{ border-color:#3d5a80; background:#1a2130; color:#e6e6e6; }}
</style>
</head>
<body>
  <h1>SecureDNS</h1>
  <p class="subtitle">Panel de control - <span id="estado-vivo">en vivo</span></p>
  {aviso_html}
  <div class="stats" id="tarjetas">{tarjetas_html}</div>
  <div id="ruido">{ruido_html}</div>

  <div class="acciones-barra">
    <button type="button" onclick="exportar()">Exportar</button>
    <form method="get" action="/clear-cache" onsubmit="return confirm('¿Borrar el cache de respuestas DNS?')">
      <button type="submit" class="danger-btn">Borrar cache</button>
    </form>
    {apagar_html}
  </div>

  <div class="tabs">
    <button class="tab-btn active" data-tab="resumen" onclick="showTab('resumen', this)">Resumen</button>
    <button class="tab-btn" data-tab="historial" onclick="showTab('historial', this)">Historial</button>
    <button class="tab-btn" data-tab="deteccion" onclick="showTab('deteccion', this)">Detección</button>
    <button class="tab-btn" data-tab="stats" onclick="showTab('stats', this)">Estadísticas</button>
    <button class="tab-btn" data-tab="blanca" onclick="showTab('blanca', this)">Lista blanca</button>
    <button class="tab-btn" data-tab="negra" onclick="showTab('negra', this)">Lista negra (manual)</button>
    <button class="tab-btn" data-tab="config" onclick="showTab('config', this)">Configuración</button>
  </div>

  <div id="tab-resumen" class="tab-panel active">
    <div id="resumen">{resumen_html}</div>
  </div>

  <div id="tab-historial" class="tab-panel">
    <h2>Historial de consultas</h2>
    {buscador}
    <table>
      <tr><th>Fecha y hora</th><th>Nombre</th><th>Tipo</th><th>Equipo</th><th>Estado</th><th>Acciones</th></tr>
      <tbody id="historial">{historial_html}</tbody>
    </table>
  </div>

  <div id="tab-deteccion" class="tab-panel">
    <h2>Detección por comportamiento</h2>
    <div id="deteccion">{deteccion_html}</div>
  </div>

  <div id="tab-stats" class="tab-panel">
    <h2>Estadísticas</h2>
    <div id="estadisticas">{estadisticas_html}</div>
  </div>

  <div id="tab-blanca" class="tab-panel">
    <h2>Lista blanca</h2>
    <p class="empty">Un dominio acá gana por sobre la blocklist. Podés pegar la
    URL entera del navegador: se limpia sola.</p>
    <form class="add-form" method="get" action="/allow">
      <input type="text" name="domain" placeholder="ejemplo.com o https://www.ejemplo.com/algo" required>
      <button type="submit">Agregar</button>
    </form>
    {allowlist_html}
  </div>

  <div id="tab-negra" class="tab-panel">
    <h2>Lista negra (manual)</h2>
    <p class="empty">Solo la lista manual (data/blocklist.txt). Lo generado por
    URLhaus/OpenPhish no se administra desde acá.</p>
    <form class="add-form" method="get" action="/blockdomain">
      <input type="text" name="domain" placeholder="ejemplo.com o https://www.ejemplo.com/algo" required>
      <button type="submit">Agregar</button>
    </form>
    {blocklist_html}
  </div>

  <div id="tab-config" class="tab-panel">
    {config_html}
  </div>

<script>
var SALTO = String.fromCharCode(10);
var TAB_STORAGE_KEY = 'securedns_dashboard_tab';
function showTab(name, btn) {{
  document.querySelectorAll('.tab-panel').forEach(function(el) {{ el.classList.remove('active'); }});
  document.querySelectorAll('.tab-btn').forEach(function(el) {{ el.classList.remove('active'); }});
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
  try {{ localStorage.setItem(TAB_STORAGE_KEY, name); }} catch (e) {{ /* sin localStorage: no pasa nada */ }}
}}
(function() {{
  var saved = null;
  try {{ saved = localStorage.getItem(TAB_STORAGE_KEY); }} catch (e) {{ /* nada */ }}
  if (saved) {{
    var btn = document.querySelector('.tab-btn[data-tab="' + saved + '"]');
    if (btn) {{ showTab(saved, btn); }}
  }}
}})();

/* El dominio viaja en data-dominio y se lee con getAttribute, que devuelve
   texto sin evaluarlo nunca. Interpolarlo dentro del onclick -como estaba
   antes- es explotable aunque se escape con html.escape: el navegador
   decodifica las entidades HTML ANTES de que el parser de JavaScript vea el
   código, así que un dominio con una comilla cerraba el string y lo que
   seguía se ejecutaba. Y los dominios de este panel vienen de la red. */
var TEXTOS_CONFIRMACION = {{
  'quitar': '¿Quitar DOMINIO?',
  'permitir': '¿Permitir siempre DOMINIO? Gana por sobre la blocklist y los feeds.',
  'bloquear': '¿Bloquear siempre DOMINIO? Se va a responder NXDOMAIN.',
  'ocultar': '¿Ocultar DOMINIO del panel? Se sigue resolviendo y registrando igual: solo deja de aparecer en el historial y en las estadísticas.',
  'normal': '¿Marcar el patrón de DOMINIO como normal? Deja de aparecer en Detección y de restar puntaje. NO es una lista blanca: se sigue filtrando y registrando igual, y podés revertirlo desde la misma pestaña.'
}};
function confirmarAccion(el, clave) {{
  var dominio = el.getAttribute('data-dominio') || '';
  var texto = TEXTOS_CONFIRMACION[clave] || '¿Seguro?';
  return confirm(texto.split('DOMINIO').join(dominio));
}}
/* Despliega la fila de detalle que ya viene en la página, sin ir al servidor.
   Funciona como acordeón: abrir uno cierra el que estuviera abierto. Con dos
   detalles abiertos a la vez la tabla se estira y hay que scrollear para
   comparar, que es lo contrario de lo que uno quiere al mirar dos consultas
   parecidas. */
function verDetalle(id) {{
  var fila = document.getElementById(id);
  if (!fila) {{ return false; }}
  var yaEstaba = fila.classList.contains('abierta');
  document.querySelectorAll('tr.detalle.abierta').forEach(function(el) {{
    el.classList.remove('abierta');
  }});
  if (!yaEstaba) {{ fila.classList.add('abierta'); }}
  return false;
}}
/* Un solo botón para exportar: se pregunta el formato y se respeta el filtro
   del buscador que esté puesto, para que lo exportado sea lo que se ve. */
function exportar() {{
  var enCSV = confirm('¿En qué formato querés exportar el historial?' + SALTO + SALTO +
                      'Aceptar = CSV (se abre con Excel)' + SALTO +
                      'Cancelar = JSON (para procesarlo con otra herramienta)');
  /* Se respetan todos los filtros que estén puestos, no solo el texto: lo que
     te llevás tiene que ser lo que estás viendo. */
  window.location = (enCSV ? '/export.csv' : '/export.json') + window.location.search;
}}
/* Apagar tiene su propia confirmación porque la consecuencia no es obvia: si
   este resolver es el DNS del sistema, apagarlo no "deja de filtrar", deja de
   traducir nombres, y todo parece caído. */
function confirmarApagado() {{
  if (!confirm('¿Apagar SecureDNS?' + SALTO + SALTO +
               'Se corta el proceso entero y tu PC vuelve a usar el DNS ' +
               'automático, así que vas a seguir navegando, pero sin filtrado ' +
               'ni cifrado de las consultas.')) {{
    return false;
  }}
  if (window.fuenteDeEventos) {{ try {{ window.fuenteDeEventos.close(); }} catch (e) {{}} }}
  return true;
}}

/* Actualización en vivo por SSE. Antes la página entera se recargaba cada 5
   segundos con un meta refresh, y eso reseteaba el scroll y borraba lo que
   estuvieras escribiendo en el buscador. */
(function() {{
  var estado = document.getElementById('estado-vivo');

  function volverAlRefresco() {{
    if (estado) {{ estado.textContent = 'se actualiza cada 5 segundos'; }}
    setTimeout(function() {{ location.reload(); }}, 5000);
  }}

  if (!window.EventSource) {{ volverAlRefresco(); return; }}

  function pintar(id, html) {{
    var nodo = document.getElementById(id);
    /* Solo se toca el DOM si el contenido cambió: si no, se pierde la
       selección de texto y parpadea sin motivo. */
    if (nodo && nodo.innerHTML !== html) {{ nodo.innerHTML = html; }}
  }}

  /* Se le pasan al canal de eventos los mismos parámetros que tiene la
     página: el texto buscado y también los filtros de tipo, categoría y
     equipo. Mandando solo el texto, la primera actualización en vivo pisaba
     el historial filtrado con uno sin filtrar. */
  var fuente = new EventSource('/eventos' + window.location.search);
  window.fuenteDeEventos = fuente;
  var fallas = 0;

  fuente.onmessage = function(evento) {{
    fallas = 0;
    if (estado) {{ estado.textContent = 'en vivo'; }}
    var datos = JSON.parse(evento.data);
    pintar('tarjetas', datos.tarjetas);
    pintar('ruido', datos.ruido);
    pintar('historial', datos.historial);
    pintar('estadisticas', datos.estadisticas);
    pintar('deteccion', datos.deteccion);
    pintar('resumen', datos.resumen);
  }};

  fuente.onerror = function() {{
    /* EventSource reconecta solo. Recién si insiste en fallar -porque el
       resolver se apagó, o no hay lugar para más pestañas- se vuelve al
       refresco clásico, para no quedar con una página congelada. */
    if (estado) {{ estado.textContent = 'reconectando...'; }}
    fallas += 1;
    if (fallas >= 3) {{ fuente.close(); volverAlRefresco(); }}
  }};
}})();
</script>
</body>
</html>"""

        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


def build_dashboard_server(
    host: str,
    port: int,
    logger_db: LoggerDB,
    allowlist: Allowlist,
    blocklist: Blocklist,
    resolver: ThreatIntelResolver,
    vista=None,
    apagar=None,
    rdap=None,
    normales=None,
) -> ThreadingHTTPServer:
    handler_class = type(
        "InjectedDashboardHandler",
        (DashboardRequestHandler,),
        {
            "logger_db": logger_db,
            "allowlist": allowlist,
            "blocklist": blocklist,
            "resolver": resolver,
            "vista": vista,
            "rdap": rdap,
            "normales": normales,
            # Envuelto en staticmethod: si `apagar` es una función suelta,
            # dejarla como atributo de clase la convertiría en método y el
            # primer argumento pasaría a ser el handler.
            "apagar": staticmethod(apagar) if callable(apagar) else None,
            # Cache de la pestaña Detección, propio de este servidor. Ver
            # `_render_deteccion`.
            "_deteccion_lock": threading.Lock(),
            "_deteccion_cache": None,
        },
    )
    server = ThreadingHTTPServer((host, port), handler_class)
    server.daemon_threads = True
    return server
