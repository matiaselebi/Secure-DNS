"""Fase 4: API de solo lectura, avisos por umbral y filtros del buscador.

Lo que atraviesa esta fase es la integración: la API existe para que
SecureCenter no tenga que raspar HTML, y los avisos existen para enterarse sin
mirar el panel. Las dos cosas tienen la misma trampa, que es avisar o exponer
de más.
"""

import json
import socket
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns.alertas import MotorDeAlertas  # noqa: E402
from securedns.blocklist import Allowlist, Blocklist  # noqa: E402
from securedns.dashboard import build_dashboard_server  # noqa: E402
from securedns.dns_server import ThreatIntelResolver, es_dominio_propio  # noqa: E402
from securedns.logger_db import LoggerDB  # noqa: E402
from securedns.view_prefs import PreferenciasDeVista  # noqa: E402


# ------------------------------------------- dominios propios del resolver


def _con_listas(tmp_path, negra="", blanca=""):
    (tmp_path / "bl.txt").write_text(negra, encoding="utf-8")
    (tmp_path / "al.txt").write_text(blanca, encoding="utf-8")
    resolver = ThreatIntelResolver(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        logger_db=LoggerDB(str(tmp_path / "l.db")),
        upstream_primary="127.0.0.1", upstream_fallback="127.0.0.1",
        allowlist=Allowlist(str(tmp_path / "al.txt")),
    )
    resolver.upstream_mode = "udp"
    return resolver


def test_un_feed_no_puede_dejar_al_resolver_sin_listas(tmp_path):
    """Si SecureDNS es el DNS del sistema, todo lo que consulta hacia afuera
    pasa por sí mismo. Con `urlhaus.abuse.ch` bloqueado por un falso positivo
    de un feed, el resolver se quedaría sin poder actualizar sus listas para
    siempre, y en silencio."""
    (tmp_path / "manual.txt").write_text("", encoding="utf-8")
    (tmp_path / "feed.txt").write_text("urlhaus.abuse.ch\n", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    resolver = ThreatIntelResolver(
        blocklist=Blocklist([str(tmp_path / "manual.txt"), str(tmp_path / "feed.txt")]),
        logger_db=LoggerDB(str(tmp_path / "l.db")),
        upstream_primary="127.0.0.1", upstream_fallback="127.0.0.1",
        allowlist=Allowlist(str(tmp_path / "al.txt")),
    )
    assert resolver._decidir("urlhaus.abuse.ch")[0] == "propio"


def test_pero_si_lo_bloqueas_a_mano_se_bloquea(tmp_path):
    """La excepción no puede pisar una decisión explícita tuya. Un bloqueo que
    el panel muestra como puesto y no se aplica es peor que no tenerlo."""
    resolver = _con_listas(tmp_path, negra="rdap.org\n")
    assert resolver._decidir("rdap.org")[0] == "bloquear"


def test_la_excepcion_es_por_nombre_exacto_y_no_por_sufijo(tmp_path):
    """Antes matcheaba por sufijo e incluía github.com entero. Eso dejaba
    exento del filtrado a cualquier subdominio de un hosting de contenido de
    terceros, y `raw.githubusercontent.com` es de los hosts más habituales en
    URLhaus para droppers y C2."""
    assert es_dominio_propio("raw.githubusercontent.com") is True
    assert es_dominio_propio("c2.raw.githubusercontent.com") is False
    assert es_dominio_propio("github.com") is False
    assert es_dominio_propio("cualquier-cosa.abuse.ch") is False
    assert es_dominio_propio("") is False


def test_la_excepcion_queda_registrada(tmp_path):
    """Que se deje pasar tiene que verse en el panel, no ser invisible."""
    from dnslib import QTYPE, RR, A, DNSRecord

    resolver = _con_listas(tmp_path)

    def upstream_ok(pedido):
        respuesta = pedido.reply()
        respuesta.add_answer(RR("rdap.org", QTYPE.A, rdata=A("1.2.3.4"), ttl=300))
        return respuesta.pack(), "upstream_primary"

    resolver._forward_via_udp = upstream_ok

    class _H:
        client_address = ("127.0.0.1", 5353)

    resolver.resolve(DNSRecord.question("rdap.org"), _H())

    fila = resolver.logger_db.buscar(solo_bloqueadas=False)[0]
    assert fila["blocked"] == 0
    assert "necesita este nombre" in fila["reason"]


def test_la_lista_blanca_sigue_ganando(tmp_path):
    """Es la regla más vieja del proyecto y no la puede cambiar nada de lo
    agregado después."""
    resolver = _con_listas(tmp_path, negra="ejemplo.com\n", blanca="ejemplo.com\n")
    assert resolver._decidir("ejemplo.com")[0] == "resolver"


# --------------------------------------------------- avisos por umbral


class _CanalFalso:
    def __init__(self):
        self.mensajes = []

    def send_alert(self, mensaje):
        self.mensajes.append(mensaje)

    def mostrar(self, titulo, cuerpo):
        self.mensajes.append(f"{titulo}: {cuerpo}")
        return True


def _motor(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    canal = _CanalFalso()
    return db, canal, MotorDeAlertas(db, telegram=canal, escritorio=None)


def test_no_avisa_por_cada_bloqueo_de_publicidad(tmp_path):
    """Un resolver con la lista de ads activada bloquea miles por día. Un aviso
    por bloqueo sería una notificación cada pocos segundos, o sea una
    herramienta que terminás apagando. Y apagada no avisa nada."""
    db, canal, motor = _motor(tmp_path)
    for i in range(300):
        db.log_query("192.168.1.10", f"ads{i}.com", "A", True,
                     source="blocklist", category="publicidad")

    motor.revisar()

    assert canal.mensajes == []


def test_avisa_por_malware(tmp_path):
    """Malware y phishing son pocos y cada uno importa."""
    db, canal, motor = _motor(tmp_path)
    db.log_query("192.168.1.20", "dropper.xyz", "A", True,
                 source="blocklist", category="malware")

    motor.revisar()

    assert len(canal.mensajes) == 1
    assert "dropper.xyz" in canal.mensajes[0]
    assert "192.168.1.20" in canal.mensajes[0]


def test_el_mismo_aviso_no_se_repite(tmp_path):
    """Si el problema sigue, ya te enteraste. Repetirlo cada minuto no agrega
    información, agrega motivos para apagar los avisos."""
    db, canal, motor = _motor(tmp_path)
    db.log_query("192.168.1.20", "dropper.xyz", "A", True,
                 source="blocklist", category="malware")
    motor.revisar()
    db.log_query("192.168.1.20", "dropper.xyz", "A", True,
                 source="blocklist", category="malware")
    motor.revisar()

    assert len(canal.mensajes) == 1


def test_cada_bloqueo_se_evalua_una_sola_vez(tmp_path):
    """Se pagina por id y no por fecha: sin eso, el motor corriendo cada minuto
    volvería a mirar las mismas filas."""
    db, canal, motor = _motor(tmp_path)
    db.log_query("192.168.1.20", "uno.xyz", "A", True, source="blocklist", category="malware")
    motor.revisar()
    db.log_query("192.168.1.20", "dos.xyz", "A", True, source="blocklist", category="malware")
    motor.revisar()

    assert len(canal.mensajes) == 2
    assert "dos.xyz" in canal.mensajes[1]


def test_hay_un_techo_de_avisos_por_hora(tmp_path):
    db, canal, motor = _motor(tmp_path)
    for i in range(20):
        db.log_query("192.168.1.20", f"malo{i}.xyz", "A", True,
                     source="blocklist", category="malware")

    motor.revisar()

    assert len(canal.mensajes) == 6


def test_un_pico_de_bloqueos_avisa(tmp_path):
    import sqlite3
    from contextlib import closing

    db, canal, motor = _motor(tmp_path)
    ahora = datetime.now(timezone.utc)
    with closing(sqlite3.connect(db.db_path)) as conn:
        # Ritmo bajo durante horas.
        for h in range(1, 7):
            for _ in range(20):
                conn.execute(
                    "INSERT INTO queries (timestamp, client_ip, domain, qtype, blocked,"
                    " reason, source, duration_ms, noisy, category, parent)"
                    " VALUES (?, '1.1.1.1', 'ads.com', 'A', 1, '', 'blocklist', 0.1, 0,"
                    " 'publicidad', 'ads.com')",
                    ((ahora - timedelta(hours=h)).isoformat(),),
                )
        # Y de golpe 300 en el último minuto.
        for _ in range(300):
            conn.execute(
                "INSERT INTO queries (timestamp, client_ip, domain, qtype, blocked,"
                " reason, source, duration_ms, noisy, category, parent)"
                " VALUES (?, '1.1.1.1', 'ads.com', 'A', 1, '', 'blocklist', 0.1, 0,"
                " 'publicidad', 'ads.com')",
                ((ahora - timedelta(seconds=20)).isoformat(),),
            )
        conn.commit()

    avisados = motor._pico_de_bloqueos()

    assert avisados == ["pico-de-bloqueos"]
    assert "Pico de bloqueos" in canal.mensajes[0]


def test_un_ritmo_bajo_no_dispara_un_pico(tmp_path):
    """Pasar de 1 bloqueo por minuto a 6 es seis veces la base y no le importa
    a nadie. Sin el piso absoluto, el aviso salta todo el tiempo."""
    db, canal, motor = _motor(tmp_path)
    for _ in range(6):
        db.log_query("1.1.1.1", "ads.com", "A", True, source="blocklist", category="publicidad")

    assert motor._pico_de_bloqueos() == []


def test_un_canal_caido_no_frena_al_otro(tmp_path):
    class _Roto:
        def send_alert(self, _m):
            raise RuntimeError("Telegram no responde")

    db = LoggerDB(str(tmp_path / "l.db"))
    escritorio = _CanalFalso()
    motor = MotorDeAlertas(db, telegram=_Roto(), escritorio=escritorio)
    db.log_query("192.168.1.20", "dropper.xyz", "A", True,
                 source="blocklist", category="malware")

    motor.revisar()

    assert len(escritorio.mensajes) == 1


def test_apagado_no_manda_nada(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    canal = _CanalFalso()
    motor = MotorDeAlertas(db, telegram=canal, escritorio=None, enabled=False)
    db.log_query("192.168.1.20", "dropper.xyz", "A", True,
                 source="blocklist", category="malware")

    motor.revisar()

    assert canal.mensajes == []


# ------------------------------------------------------- API y filtros


@pytest.fixture()
def panel(tmp_path):
    (tmp_path / "bl.txt").write_text("", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    (tmp_path / "ruido.txt").write_text("telemetria.test\n", encoding="utf-8")
    blocklist = Blocklist(str(tmp_path / "bl.txt"))
    allowlist = Allowlist(str(tmp_path / "al.txt"))
    db = LoggerDB(str(tmp_path / "l.db"))
    resolver = ThreatIntelResolver(
        blocklist=blocklist, logger_db=db,
        upstream_primary="127.0.0.1", upstream_fallback="127.0.0.1",
        allowlist=allowlist,
    )
    vista = PreferenciasDeVista(Blocklist(str(tmp_path / "ruido.txt")), ocultar_ruido=True)
    servidor = build_dashboard_server(
        "127.0.0.1", 0, db, allowlist, blocklist, resolver, vista=vista,
    )
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield servidor.server_address[1], db, blocklist
    finally:
        servidor.shutdown()


def _crudo(puerto, ruta, host=None) -> str:
    con = socket.create_connection(("127.0.0.1", puerto), timeout=5)
    try:
        cabecera = host or f"127.0.0.1:{puerto}"
        con.sendall(
            f"GET {ruta} HTTP/1.1\r\nHost: {cabecera}\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        con.settimeout(5)
        datos = b""
        try:
            while len(datos) < 1_000_000:
                trozo = con.recv(8192)
                if not trozo:
                    break
                datos += trozo
        except socket.timeout:
            pass
        return datos.decode("utf-8", "replace")
    finally:
        con.close()


def _json(puerto, ruta):
    respuesta = _crudo(puerto, ruta)
    return json.loads(respuesta.split("\r\n\r\n", 1)[1])


def test_el_indice_lista_los_recursos(panel):
    puerto, _db, _bl = panel
    datos = _json(puerto, "/api")
    assert datos["servicio"] == "SecureDNS"
    assert "/api/estado" in datos["recursos"]


def test_estado_trae_lo_que_necesita_secure_center(panel):
    """Es la tarjeta de estado: con esto SecureCenter no necesita raspar el
    HTML del panel, que se rompe con cada cambio de diseño."""
    puerto, db, _bl = panel
    db.log_query("1.1.1.1", "a.com", "A", False, source="cache")
    db.log_query("1.1.1.1", "malo.com", "A", True, source="blocklist", category="malware")

    datos = _json(puerto, "/api/estado")

    assert datos["vivo"] is True
    assert datos["consultas"] == 2
    assert datos["bloqueadas"] == 1
    assert datos["tasa_de_bloqueo"] == pytest.approx(50.0)
    assert "modo_upstream" in datos
    assert "hallazgos_abiertos" in datos


def test_el_historial_por_api_respeta_el_limite(panel):
    puerto, db, _bl = panel
    for i in range(40):
        db.log_query("1.1.1.1", f"d{i}.com", "A", False, source="cache")

    datos = _json(puerto, "/api/historial?limite=5")

    assert len(datos["consultas"]) == 5


def test_un_limite_absurdo_no_baja_el_servicio(panel):
    """Un `limite=99999999` que se pasara tal cual a la consulta traería la
    tabla entera a memoria."""
    puerto, db, _bl = panel
    for i in range(20):
        db.log_query("1.1.1.1", f"d{i}.com", "A", False, source="cache")

    datos = _json(puerto, "/api/historial?limite=99999999")

    assert len(datos["consultas"]) == 20  # el tope se aplicó, no reventó


def test_un_limite_que_no_es_numero_no_rompe(panel):
    puerto, _db, _bl = panel
    datos = _json(puerto, "/api/historial?limite=quiero-todo")
    assert "consultas" in datos


def test_un_recurso_inventado_da_404_y_dice_cuales_hay(panel):
    puerto, _db, _bl = panel
    respuesta = _crudo(puerto, "/api/cualquier-cosa")
    assert "404" in respuesta.split("\r\n")[0]
    datos = json.loads(respuesta.split("\r\n\r\n", 1)[1])
    assert "/api/estado" in datos["recursos"]


def test_la_api_no_manda_cors(panel):
    """Sin `Access-Control-Allow-Origin`, el navegador no deja que una página
    de otro origen LEA las respuestas. Agregarlo por comodidad abriría el
    historial de DNS de toda la casa a cualquier sitio que visites."""
    puerto, _db, _bl = panel
    respuesta = _crudo(puerto, "/api/estado")
    assert "access-control-allow-origin" not in respuesta.lower()


def test_la_api_no_se_deja_alcanzar_por_rebinding(panel):
    """Mismo chequeo de Host que el panel: acá hay para leer el historial de
    DNS de toda la casa."""
    puerto, _db, _bl = panel
    respuesta = _crudo(puerto, "/api/estado", host="attacker.com")
    assert "403" in respuesta.split("\r\n")[0]


def test_la_api_no_se_cachea(panel):
    puerto, _db, _bl = panel
    respuesta = _crudo(puerto, "/api/estado")
    assert "no-store" in respuesta.lower()


def test_las_listas_por_api(panel):
    puerto, _db, blocklist = panel
    blocklist.add_and_reload("bloqueado-a-mano.com")

    datos = _json(puerto, "/api/listas")

    assert "bloqueado-a-mano.com" in datos["lista_negra_manual"]


# ----------------------------------------------- filtros del buscador


def test_filtrar_por_tipo(panel):
    _puerto, db, _bl = panel
    db.log_query("1.1.1.1", "a.com", "A", False, source="cache")
    db.log_query("1.1.1.1", "b.com", "TXT", False, source="cache")

    filas = db.buscar(solo_bloqueadas=False, qtype="TXT")

    assert [f["domain"] for f in filas] == ["b.com"]


def test_filtrar_por_categoria(panel):
    _puerto, db, _bl = panel
    db.log_query("1.1.1.1", "a.com", "A", True, source="blocklist", category="malware")
    db.log_query("1.1.1.1", "b.com", "A", True, source="blocklist", category="publicidad")

    filas = db.buscar(categoria="malware")

    assert [f["domain"] for f in filas] == ["a.com"]


def test_filtrar_por_equipo(panel):
    _puerto, db, _bl = panel
    db.log_query("192.168.1.10", "a.com", "A", False, source="cache")
    db.log_query("192.168.1.99", "b.com", "A", False, source="cache")

    filas = db.buscar(solo_bloqueadas=False, cliente="192.168.1.99")

    assert [f["domain"] for f in filas] == ["b.com"]


def test_los_filtros_se_combinan_con_la_busqueda(panel):
    _puerto, db, _bl = panel
    db.log_query("192.168.1.10", "algo.ejemplo.com", "TXT", False, source="cache")
    db.log_query("192.168.1.10", "algo.ejemplo.com", "A", False, source="cache")
    db.log_query("192.168.1.99", "otro.ejemplo.com", "TXT", False, source="cache")

    filas = db.buscar(texto="ejemplo", qtype="TXT", cliente="192.168.1.10")

    assert len(filas) == 1
    assert filas[0]["qtype"] == "TXT"
    assert filas[0]["client_ip"] == "192.168.1.10"


def test_el_panel_muestra_los_filtros_puestos(panel):
    puerto, db, _bl = panel
    db.log_query("192.168.1.99", "a.com", "A", True, source="blocklist", category="malware")

    pagina = _crudo(puerto, "/?cat=malware&cliente=192.168.1.99")

    assert "de categoría" in pagina
    assert "del equipo" in pagina
    assert "Limpiar y ver solo los últimos bloqueos" in pagina


def test_las_opciones_del_filtro_salen_de_lo_que_hay(panel):
    """Ofrecer un filtro por NULL cuando nunca llegó una consulta NULL es
    prometer algo que va a devolver cero."""
    puerto, db, _bl = panel
    db.log_query("1.1.1.1", "a.com", "HTTPS", False, source="cache")

    pagina = _crudo(puerto, "/")

    assert "<option value='HTTPS'" in pagina
    assert "<option value='NULL'" not in pagina


def test_el_canal_en_vivo_no_pisa_los_filtros(panel):
    """Bug real: se ponía un filtro, y cinco segundos después la primera
    actualización en vivo lo reemplazaba por el historial sin filtrar. El
    filtro parecía no funcionar, cuando en realidad funcionaba y se lo comía
    el refresco."""
    puerto, db, _bl = panel
    db.log_query("1.1.1.1", "malo.com", "A", True, source="blocklist", category="malware")
    db.log_query("1.1.1.1", "ads.com", "A", True, source="blocklist", category="publicidad")

    con = socket.create_connection(("127.0.0.1", puerto), timeout=8)
    try:
        con.sendall(
            f"GET /eventos?cat=malware HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        con.settimeout(8)
        datos = b""
        while b"\n\n" not in datos.split(b"\r\n\r\n", 1)[-1]:
            trozo = con.recv(8192)
            if not trozo:
                break
            datos += trozo
    finally:
        con.close()

    texto = datos.decode("utf-8", "replace")
    # Se mira el fragmento del historial y no el mensaje entero: las
    # estadísticas que viajan en el mismo evento son del total y no del filtro,
    # así que ahí "ads.com" aparece con razón.
    carga = texto.split("data: ", 1)[1].split("\n\n", 1)[0]
    historial = json.loads(carga)["historial"]
    assert "malo.com" in historial
    assert "ads.com" not in historial


def test_exportar_respeta_los_filtros(panel):
    puerto, db, _bl = panel
    db.log_query("1.1.1.1", "malo.com", "A", True, source="blocklist", category="malware")
    db.log_query("1.1.1.1", "ads.com", "A", True, source="blocklist", category="publicidad")

    respuesta = _crudo(puerto, "/export.csv?cat=malware")

    assert "malo.com" in respuesta
    assert "ads.com" not in respuesta


def test_el_contador_no_cuenta_doble(panel):
    """La fila de detalle es un `<tr>` más por consulta. Contando `<tr>` sobre
    el HTML, el panel decía el doble de lo que había."""
    puerto, db, _bl = panel
    for i in range(3):
        db.log_query("1.1.1.1", f"malo{i}.com", "A", True,
                     source="blocklist", category="malware")

    pagina = _crudo(puerto, "/?cat=malware")

    assert "3 consultas de categoría" in pagina
