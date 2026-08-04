"""Todo lo que el panel de SecureDNS ganó al emparejarlo con SecureProxy.

Tres grupos:

1. Las defensas que faltaban (CSRF, DNS rebinding, el XSS de los onclick).
   Estos no son features: eran agujeros abiertos, y cada test dice cuál.
2. El historial de verdad: hora local, buscador, filtro de ruido.
3. Lo nuevo del panel: niveles, dominios limpios, apagado.
"""

import socket
import sys
import threading
import time
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns.blocklist import Allowlist, Blocklist  # noqa: E402
from securedns.dashboard import (  # noqa: E402
    build_dashboard_server,
    formatear_fecha,
    hora_local,
)
from securedns.dns_server import ThreatIntelResolver  # noqa: E402
from securedns.logger_db import LoggerDB  # noqa: E402
from securedns.validation import (  # noqa: E402
    limpiar_para_mostrar,
    normalizar_dominio,
    normalizar_nombre_consultado,
)
from securedns.view_prefs import PreferenciasDeVista  # noqa: E402


# ---------------------------------------------------------------- helpers


def _armar(tmp_path, apagar=None, ocultar=True):
    (tmp_path / "bl.txt").write_text("", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    (tmp_path / "ruido.txt").write_text(
        "connectivity-check.ubuntu.com\ntelemetry.microsoft.com\n", encoding="utf-8"
    )
    blocklist = Blocklist(str(tmp_path / "bl.txt"))
    allowlist = Allowlist(str(tmp_path / "al.txt"))
    logger_db = LoggerDB(str(tmp_path / "logs.db"))
    resolver = ThreatIntelResolver(
        blocklist=blocklist, logger_db=logger_db,
        upstream_primary="127.0.0.1", upstream_fallback="127.0.0.1",
        allowlist=allowlist,
    )
    vista = PreferenciasDeVista(
        Blocklist(str(tmp_path / "ruido.txt")), ocultar_ruido=ocultar
    )
    resolver.vista = vista
    servidor = build_dashboard_server(
        "127.0.0.1", 0, logger_db, allowlist, blocklist, resolver,
        vista=vista, apagar=apagar,
    )
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return servidor, logger_db, blocklist, allowlist, vista


def _cruda(puerto, pedido: str, espera=4.0) -> str:
    con = socket.create_connection(("127.0.0.1", puerto), timeout=espera)
    try:
        con.sendall(pedido.encode())
        con.settimeout(espera)
        datos = b""
        try:
            while len(datos) < 262144:
                trozo = con.recv(8192)
                if not trozo:
                    break
                datos += trozo
        except socket.timeout:
            pass
        return datos.decode("utf-8", "replace")
    finally:
        con.close()


@pytest.fixture()
def panel(tmp_path):
    servidor, db, bl, al, vista = _armar(tmp_path)
    try:
        yield servidor.server_address[1], db, bl, al, vista
    finally:
        servidor.shutdown()


# ------------------------------------------------- 1. defensas del panel


ACCIONES = [
    "/config?k=upstream_mode&v=udp",
    "/nivel?v=paranoico",
    "/allow?domain=c2.attacker.com",
    "/blockdomain?domain=banco.com",
    "/ocultar?domain=c2.attacker.com",
    "/clear-cache",
    "/borrar-historial",
    "/apagar",
]


@pytest.mark.parametrize("ruta", ACCIONES)
def test_una_web_cualquiera_no_puede_tocar_el_resolver(panel, ruta):
    """CSRF. Todas las acciones del panel son GET sin token, así que
    cualquier página que visites podía hacer
    <img src="http://127.0.0.1:8890/config?k=upstream_mode&v=udp"> y dejar tus
    consultas DNS viajando en texto plano, o meter su propio dominio en la
    lista blanca donde ningún feed lo va a poder frenar. No hace falta leer la
    respuesta para que el daño esté hecho, así que la política de mismo origen
    del navegador no protegía de esto."""
    puerto = panel[0]
    respuesta = _cruda(puerto, (
        f"GET {ruta} HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\n"
        "Sec-Fetch-Site: cross-site\r\nOrigin: https://sitio-malicioso.com\r\n"
        "Connection: close\r\n\r\n"
    ))
    assert "403" in respuesta.split("\r\n")[0]


@pytest.mark.parametrize("ruta", ACCIONES)
def test_tambien_se_frena_por_referer(panel, ruta):
    """Los navegadores viejos no mandan Sec-Fetch-Site."""
    puerto = panel[0]
    respuesta = _cruda(puerto, (
        f"GET {ruta} HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\n"
        "Referer: https://sitio-malicioso.com/pagina\r\n"
        "Connection: close\r\n\r\n"
    ))
    assert "403" in respuesta.split("\r\n")[0]


def test_dns_rebinding_al_panel_del_dns(panel):
    """Un atacante publica attacker.com con TTL 0, te hace entrar, y después
    reapunta ese nombre a 127.0.0.1: a partir de ahí su JavaScript es del
    mismo origen que el panel y puede LEER las respuestas. Y acá lo que hay
    para leer es el historial de DNS de toda la casa. El navegador manda en
    Host el nombre que el usuario escribió, así que con eso alcanza."""
    puerto = panel[0]
    respuesta = _cruda(puerto, (
        f"GET / HTTP/1.1\r\nHost: attacker.com\r\nConnection: close\r\n\r\n"
    ))
    assert "403" in respuesta.split("\r\n")[0]


def test_el_panel_propio_si_puede(panel):
    puerto = panel[0]
    respuesta = _cruda(puerto, (
        f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\n"
        "Sec-Fetch-Site: same-origin\r\nConnection: close\r\n\r\n"
    ))
    assert "200" in respuesta.split("\r\n")[0]


def test_health_no_pide_permiso(panel):
    """Lo consulta SecureCenter para saber si el resolver está vivo: no
    cambia nada y no expone datos, así que queda afuera del chequeo."""
    puerto = panel[0]
    respuesta = _cruda(puerto, (
        "GET /health HTTP/1.1\r\nHost: cualquier-cosa\r\nConnection: close\r\n\r\n"
    ))
    assert "200" in respuesta.split("\r\n")[0]
    assert respuesta.rstrip().endswith("ok")


def test_el_dominio_no_se_interpola_dentro_del_javascript(panel):
    """XSS. El dominio de una consulta viene de la RED: lo elige quien tenga
    un equipo en tu casa, o el malware que corre en él. Estaba metido dentro
    del onclick, y ahí escapar con html.escape no alcanza: el navegador
    decodifica las entidades HTML ANTES de que el parser de JavaScript vea el
    código, así que &#39; vuelve a ser una comilla, cierra el string y lo que
    sigue se ejecuta. Ahora el dominio viaja en data-dominio y se lee con
    getAttribute, que devuelve texto y no lo evalúa nunca."""
    puerto, db, _bl, _al, _vista = panel
    veneno = "x';alert(1);'.com"
    db.log_query("192.168.1.5", veneno, "A", True, reason="prueba", source="blocklist")

    pagina = _cruda(puerto, (
        f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\nConnection: close\r\n\r\n"
    ))

    assert "alert(1)" not in pagina.replace("&#x27;", "'").split("<script>")[1]
    assert "data-dominio=" in pagina
    assert "confirmarAccion(this," in pagina


# --------------------------------------------- 2. historial de verdad


def test_la_hora_es_local_y_no_utc():
    """El panel mostraba UTC con un "(UTC)" al lado como disculpa. La hora
    que le sirve a alguien mirando su propio DNS es la de su reloj."""
    from datetime import datetime, timezone

    momento = datetime(2026, 7, 27, 3, 9, 15, tzinfo=timezone.utc)
    texto = formatear_fecha(momento.isoformat())
    esperado = momento.astimezone().strftime("%d/%m/%Y %H:%M:%S")
    assert texto == esperado


def test_una_fecha_ilegible_no_rompe_el_panel():
    assert formatear_fecha("no soy una fecha") == "no soy una fecha"
    assert hora_local("cualquiera") == "cualquiera"


def test_el_grafico_usa_la_misma_hora_que_la_tabla():
    """El agrupamiento se hace sobre el timestamp en UTC. Sin convertir, las
    barras quedaban corridas respecto del historial, que sí muestra hora
    local, y las dos hablaban de cosas distintas."""
    from datetime import datetime, timezone

    esperado = datetime(2026, 7, 29, 5, tzinfo=timezone.utc).astimezone().strftime("%H:00")
    assert hora_local("2026-07-29T05") == esperado


def test_el_historial_muestra_todo_y_no_solo_25_bloqueos(panel):
    puerto, db, _bl, _al, _vista = panel
    for i in range(60):
        db.log_query("192.168.1.5", f"malo{i}.test", "A", True, reason="x", source="blocklist")
    filas = db.buscar(limit=50)
    assert len(filas) == 50
    assert filas[0]["domain"] == "malo59.test"


def test_buscar_trae_las_resueltas_tambien(panel):
    """Si estás auditando qué hizo un equipo querés ver todo, no solo lo que
    se le bloqueó."""
    _puerto, db, _bl, _al, _vista = panel
    db.log_query("192.168.1.9", "resuelto.test", "A", False, source="upstream_primary_dot")
    db.log_query("192.168.1.9", "bloqueado.test", "A", True, reason="x", source="blocklist")

    solo_bloqueos = db.buscar()
    busqueda = db.buscar(texto="192.168.1.9")

    assert [f["domain"] for f in solo_bloqueos] == ["bloqueado.test"]
    assert {f["domain"] for f in busqueda} == {"resuelto.test", "bloqueado.test"}


# ------------------------------------------------- 3. filtro de ruido


def test_el_ruido_sale_del_top_y_de_los_totales(panel):
    _puerto, db, _bl, _al, vista = panel
    for _ in range(30):
        db.log_query("192.168.1.5", "connectivity-check.ubuntu.com", "A", False,
                     source="cache", noisy=True)
    db.log_query("192.168.1.5", "github.com", "A", False, source="cache")

    con_filtro = db.stats(ocultar=True)
    sin_filtro = db.stats(ocultar=False)
    top = db.top_dominios(10, ocultar=True)

    assert sin_filtro["total_queries"] == 31
    assert con_filtro["total_queries"] == 1
    assert [d for d, _c in top] == ["github.com"]


def test_el_panel_siempre_dice_cuantas_oculto(panel):
    """La regla que hace honesto al filtro: esconder cosas sin decir cuántas
    sería un panel de seguridad que miente."""
    puerto, db, _bl, _al, _vista = panel
    for _ in range(7):
        db.log_query("192.168.1.5", "telemetry.microsoft.com", "A", False,
                     source="cache", noisy=True)

    pagina = _cruda(puerto, (
        f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\nConnection: close\r\n\r\n"
    ))

    assert "Se están ocultando" in pagina
    assert "<strong>7</strong>" in pagina


def test_buscar_un_dominio_ruidoso_igual_lo_encuentra(panel):
    """Si lo estás buscando, es porque lo querés ver."""
    _puerto, db, _bl, _al, _vista = panel
    db.log_query("192.168.1.5", "telemetry.microsoft.com", "A", False,
                 source="cache", noisy=True)

    assert db.buscar(texto="telemetry", ocultar=True)


def test_el_filtro_no_borra_ni_un_dato(panel):
    _puerto, db, _bl, _al, _vista = panel
    db.log_query("192.168.1.5", "telemetry.microsoft.com", "A", False,
                 source="cache", noisy=True)
    assert db.stats(ocultar=False)["total_queries"] == 1
    assert db.stats(ocultar=True)["total_queries"] == 0
    # Sigue en la base, entero.
    assert db.buscar(texto="telemetry")[0]["domain"] == "telemetry.microsoft.com"


def test_remarcar_arregla_una_base_vieja_y_tambien_desmarca(panel):
    """Al arrancar se recalcula todo el historial: una base que ya existía, o
    una lista editada a mano, quedan consistentes desde el primer refresco."""
    _puerto, db, _bl, _al, vista = panel
    db.log_query("192.168.1.5", "telemetry.microsoft.com", "A", False, source="cache")
    assert db.stats(ocultar=True)["total_queries"] == 1  # todavía sin marcar

    assert db.remarcar_ruido(vista.es_ruidoso) == 1
    assert db.stats(ocultar=True)["total_queries"] == 0

    vista.quitar("telemetry.microsoft.com")
    # La lista de fábrica del test tiene ese dominio en el archivo, así que
    # quitarlo lo saca de verdad: al remarcar vuelve a contarse.
    assert db.remarcar_ruido(vista.es_ruidoso) == 1
    assert db.stats(ocultar=True)["total_queries"] == 1


def test_ocultar_desde_el_panel_remarca_en_el_momento(panel):
    puerto, db, _bl, _al, _vista = panel
    db.log_query("192.168.1.5", "ruidoso.test", "A", False, source="cache")
    assert db.stats(ocultar=True)["total_queries"] == 1

    requests.get(f"http://127.0.0.1:{puerto}/ocultar?domain=ruidoso.test",
                 timeout=5, allow_redirects=False)

    assert db.stats(ocultar=True)["total_queries"] == 0


# --------------------------------------- 4. dominios limpios y niveles


def test_una_url_pegada_termina_siendo_un_dominio():
    dominio, avisos = normalizar_dominio("https://www.Ejemplo.com:8443/algo?x=1")
    assert dominio == "ejemplo.com"
    assert any("http" in a for a in avisos)
    assert any("camino" in a for a in avisos)
    assert any("puerto" in a for a in avisos)
    assert any("www" in a for a in avisos)


def test_en_dns_el_www_no_se_tapa_al_mostrar():
    """Diferencia deliberada con SecureProxy: en el proxy se muestra a qué
    SITIO fuiste, y www.ejemplo.com y ejemplo.com son el mismo sitio. En un
    resolver son dos NOMBRES distintos, que pueden apuntar a IPs distintas.
    Taparlo haría que dos filas legítimamente diferentes se vean iguales."""
    assert limpiar_para_mostrar("www.ejemplo.com") == "www.ejemplo.com"
    assert limpiar_para_mostrar("ejemplo.com.") == "ejemplo.com"


def test_el_punto_final_del_fqdn_no_es_un_bypass():
    """"nanopool.org." y "nanopool.org" son el mismo nombre para el DNS y
    resuelven igual, pero las listas comparan texto: con el punto al final no
    matcheaba nada y la consulta pasaba limpita."""
    assert normalizar_nombre_consultado("Nanopool.ORG.") == "nanopool.org"


def test_un_nombre_internacional_se_compara_en_punycode():
    """Los feeds publican en punycode; comparar en Unicode no matchea."""
    assert normalizar_nombre_consultado("тест.com").startswith("xn--")


def test_el_nivel_paranoico_exige_cifrado(panel):
    puerto, _db, _bl, _al, _vista = panel
    requests.get(f"http://127.0.0.1:{puerto}/nivel?v=paranoico", timeout=5,
                 allow_redirects=False)
    pagina = requests.get(f"http://127.0.0.1:{puerto}/", timeout=5).text
    assert "Paranoico" in pagina


def test_un_nivel_inventado_no_hace_nada(panel):
    puerto, _db, _bl, _al, _vista = panel
    r = requests.get(f"http://127.0.0.1:{puerto}/nivel?v=ultra-mega", timeout=5,
                     allow_redirects=False)
    assert r.status_code == 303


# ----------------------------------------------------- 5. apagar


def test_apagar_contesta_antes_de_apagar(tmp_path):
    """Si el proceso se cerrara antes de mandar la respuesta, el navegador
    mostraría "no se puede conectar" justo cuando la acción salió bien."""
    llamadas = []
    servidor, *_ = _armar(tmp_path, apagar=lambda: llamadas.append(1))
    try:
        puerto = servidor.server_address[1]
        respuesta = _cruda(puerto, (
            f"GET /apagar HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\n"
            "Connection: close\r\n\r\n"
        ))
        assert "200" in respuesta.split("\r\n")[0]
        assert "SecureDNS apagado" in respuesta
        assert llamadas == []
        for _ in range(40):
            if llamadas:
                break
            time.sleep(0.1)
        assert len(llamadas) == 1
    finally:
        servidor.shutdown()


def test_la_despedida_habla_del_dns_del_sistema(tmp_path):
    """La consecuencia que importa no es "deja de filtrar" sino qué pasa con
    el DNS de la máquina, que es lo que dejaba a alguien sin navegar. La
    página dice que se restauró, y qué hacer si no."""
    servidor, *_ = _armar(tmp_path, apagar=lambda: None)
    try:
        puerto = servidor.server_address[1]
        respuesta = _cruda(puerto, (
            f"GET /apagar HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\n"
            "Connection: close\r\n\r\n"
        ))
        assert "volvió a automático" in respuesta
        assert "ResetServerAddresses" in respuesta
    finally:
        servidor.shutdown()


def test_sin_forma_de_apagar_no_se_muestra_el_boton(tmp_path):
    servidor, *_ = _armar(tmp_path, apagar=None)
    try:
        puerto = servidor.server_address[1]
        pagina = _cruda(puerto, (
            f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\nConnection: close\r\n\r\n"
        ))
        assert "Apagar resolver" not in pagina
        assert 'action="/apagar"' not in pagina
    finally:
        servidor.shutdown()


# ------------------------------------------- 6. retención del historial


def test_el_historial_se_recorta_solo(tmp_path):
    """Sin tope, un resolver que atiende a toda la casa llena el disco: cada
    página web dispara decenas de consultas."""
    db = LoggerDB(str(tmp_path / "logs.db"), max_rows=10)
    for i in range(25):
        db.log_query("192.168.1.5", f"d{i}.test", "A", False, source="cache")

    assert db.prune() == 15
    filas = db.buscar(solo_bloqueadas=False, limit=100)
    assert len(filas) == 10
    # Se conservan las MÁS RECIENTES, que son las que el panel muestra.
    assert filas[0]["domain"] == "d24.test"


def test_max_rows_cero_es_sin_limite(tmp_path):
    db = LoggerDB(str(tmp_path / "logs.db"), max_rows=0)
    for i in range(30):
        db.log_query("192.168.1.5", f"d{i}.test", "A", False, source="cache")
    assert db.prune() == 0
    assert len(db.buscar(solo_bloqueadas=False, limit=100)) == 30


def test_el_cache_del_resolver_tiene_techo(tmp_path):
    """Sin techo, el cache es un agujero de memoria con forma de feature:
    cualquier cosa que consulte nombres distintos sin parar -malware con
    dominios generados por algoritmo, tunneling por DNS- lo llena hasta que
    el proceso se queda sin RAM."""
    (tmp_path / "bl.txt").write_text("", encoding="utf-8")
    resolver = ThreatIntelResolver(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        logger_db=LoggerDB(str(tmp_path / "logs.db")),
        upstream_primary="127.0.0.1", upstream_fallback="127.0.0.1",
    )
    resolver.MAX_CACHE = 100
    for i in range(300):
        resolver._guardar_en_cache((f"d{i}.test", 1), b"x", 300)

    assert resolver.cache_size() <= 100
