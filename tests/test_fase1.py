"""Fase 1: mostrar lo que ya se estaba guardando, y las categorías.

Casi todo lo de esta fase sale de datos que la base ya tenía y que el panel
no usaba (`duration_ms`, `source`, las bloqueadas por cliente). Lo único
verdaderamente nuevo son las categorías de bloqueo y los modos de respuesta.

La regla que atraviesa todos estos tests: **la categoría no se inventa**.
Sale del feed donde apareció el dominio. Si no hay marca, se dice "amenaza" y
no se elige una categoría linda al azar.
"""

import socket
import sys
import threading
import time
from pathlib import Path

import pytest
import requests
from dnslib import QTYPE, RCODE, DNSRecord

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns.blocklist import Allowlist, Blocklist, nombre_de_categoria  # noqa: E402
from securedns.dashboard import build_dashboard_server  # noqa: E402
from securedns.dns_server import ThreatIntelResolver  # noqa: E402
from securedns.logger_db import LoggerDB  # noqa: E402
from securedns.view_prefs import PreferenciasDeVista  # noqa: E402


# ------------------------------------------------------- categorías


def test_la_categoria_sale_de_la_marca_del_feed(tmp_path):
    manual = tmp_path / "manual.txt"
    feeds = tmp_path / "feeds.txt"
    manual.write_text("puesto-a-mano.com\n", encoding="utf-8")
    feeds.write_text(
        "# Generado automaticamente\n"
        "# categoria: malware\n"
        "dropper.xyz\n"
        "\n"
        "# categoria: phishing\n"
        "banco-falso.tk\n",
        encoding="utf-8",
    )
    lista = Blocklist([str(manual), str(feeds)])

    assert lista.categoria_de("dropper.xyz") == "malware"
    assert lista.categoria_de("banco-falso.tk") == "phishing"
    assert lista.categoria_de("puesto-a-mano.com") == "manual"


def test_un_archivo_sin_marcas_sigue_funcionando(tmp_path):
    """Compatibilidad hacia atrás: un blocklist_feeds.txt generado antes de que
    las marcas existieran no puede romper el resolver. Queda como "amenaza",
    que es lo honesto: sabemos que está bloqueado y no sabemos de qué es."""
    manual = tmp_path / "m.txt"
    viejo = tmp_path / "viejo.txt"
    manual.write_text("", encoding="utf-8")
    viejo.write_text("# Generado automaticamente\nalgo-malo.com\n", encoding="utf-8")
    lista = Blocklist([str(manual), str(viejo)])

    assert lista.is_blocked("algo-malo.com")
    assert lista.categoria_de("algo-malo.com") == "amenaza"


def test_un_dominio_en_dos_feeds_no_cambia_de_categoria_solo(tmp_path):
    """Si el mismo dominio aparece en dos secciones, gana la primera. Sin esto
    el orden de lectura decidiría en silencio si algo es malware o publicidad,
    y podría cambiar de un día para el otro sin que nadie toque nada."""
    manual = tmp_path / "m.txt"
    feeds = tmp_path / "f.txt"
    manual.write_text("", encoding="utf-8")
    feeds.write_text(
        "# categoria: malware\nrepetido.com\n# categoria: publicidad\nrepetido.com\n",
        encoding="utf-8",
    )
    lista = Blocklist([str(manual), str(feeds)])

    assert lista.categoria_de("repetido.com") == "malware"


def test_un_subdominio_hereda_la_categoria_del_padre(tmp_path):
    manual = tmp_path / "m.txt"
    feeds = tmp_path / "f.txt"
    manual.write_text("", encoding="utf-8")
    feeds.write_text("# categoria: publicidad\ndoubleclick.net\n", encoding="utf-8")
    lista = Blocklist([str(manual), str(feeds)])

    assert lista.is_blocked("stats.g.doubleclick.net")
    assert lista.categoria_de("stats.g.doubleclick.net") == "publicidad"


def test_un_dominio_permitido_no_tiene_categoria(tmp_path):
    manual = tmp_path / "m.txt"
    manual.write_text("malo.com\n", encoding="utf-8")
    lista = Blocklist([str(manual)])

    assert lista.categoria_de("cualquier-otra-cosa.com") == ""


def test_una_categoria_desconocida_se_muestra_tal_cual():
    """Si un feed nuevo trae una categoría que no está en la tabla, se muestra
    como vino en vez de inventarle un nombre lindo."""
    assert nombre_de_categoria("malware") == "Malware"
    assert nombre_de_categoria("categoria-rarisima") == "categoria-rarisima"


def test_el_generador_escribe_las_marcas(tmp_path):
    """La otra mitad: si update_blocklist deja de escribir las marcas, las
    categorías se apagan solas y nadie se entera."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import update_blocklist

    salida = tmp_path / "feeds.txt"
    with open(salida, "w", encoding="utf-8") as f:
        update_blocklist._escribir_bloque(f, "malware", {"a.com", "b.com"})
        update_blocklist._escribir_bloque(f, "phishing", {"c.com"})

    texto = salida.read_text(encoding="utf-8")
    assert "# categoria: malware" in texto
    assert "# categoria: phishing" in texto

    manual = tmp_path / "m.txt"
    manual.write_text("", encoding="utf-8")
    lista = Blocklist([str(manual), str(salida)])
    assert lista.categoria_de("a.com") == "malware"
    assert lista.categoria_de("c.com") == "phishing"


# --------------------------------------------------- modos de bloqueo


def _resolver(tmp_path, modo="nxdomain"):
    (tmp_path / "bl.txt").write_text(
        "# categoria: publicidad\nbloqueado.test\n", encoding="utf-8"
    )
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    return ThreatIntelResolver(
        blocklist=Blocklist([str(tmp_path / "bl.txt")]),
        logger_db=LoggerDB(str(tmp_path / "l.db")),
        upstream_primary="127.0.0.1", upstream_fallback="127.0.0.1",
        allowlist=Allowlist(str(tmp_path / "al.txt")),
        block_mode=modo,
    )


class _HandlerFalso:
    client_address = ("192.168.1.50", 5353)


def _preguntar(resolver, nombre, tipo="A"):
    pedido = DNSRecord.question(nombre, tipo)
    return resolver.resolve(pedido, _HandlerFalso())


def test_nxdomain_es_el_modo_por_defecto(tmp_path):
    respuesta = _preguntar(_resolver(tmp_path), "bloqueado.test")
    assert respuesta.header.rcode == RCODE.NXDOMAIN
    assert respuesta.rr == []


def test_modo_zero_responde_la_direccion_nula(tmp_path):
    """El nombre existe pero no va a ninguna parte: la conexión falla al
    instante en vez de que la aplicación crea que se cayó la red."""
    respuesta = _preguntar(_resolver(tmp_path, "zero"), "bloqueado.test")
    assert respuesta.header.rcode == RCODE.NOERROR
    assert str(respuesta.rr[0].rdata) == "0.0.0.0"


def test_modo_localhost_responde_a_la_propia_maquina(tmp_path):
    respuesta = _preguntar(_resolver(tmp_path, "localhost"), "bloqueado.test")
    assert str(respuesta.rr[0].rdata) == "127.0.0.1"


def test_los_modos_tambien_valen_para_ipv6(tmp_path):
    cero = _preguntar(_resolver(tmp_path, "zero"), "bloqueado.test", "AAAA")
    local = _preguntar(_resolver(tmp_path, "localhost"), "bloqueado.test", "AAAA")
    assert str(cero.rr[0].rdata) == "::"
    assert str(local.rr[0].rdata) == "::1"


@pytest.mark.parametrize("modo", ["zero", "localhost"])
def test_un_tipo_que_no_es_direccion_siempre_da_nxdomain(tmp_path, modo):
    """No se puede fabricar un TXT que signifique "bloqueado". Devolver una
    respuesta inventada sería peor que decir que el nombre no existe."""
    respuesta = _preguntar(_resolver(tmp_path, modo), "bloqueado.test", "TXT")
    assert respuesta.header.rcode == RCODE.NXDOMAIN
    assert respuesta.rr == []


def test_un_modo_inventado_cae_en_nxdomain(tmp_path):
    """Si alguien escribe cualquier cosa en el config.yaml, el resolver no se
    rompe: usa el modo más conservador."""
    respuesta = _preguntar(_resolver(tmp_path, "modo-que-no-existe"), "bloqueado.test")
    assert respuesta.header.rcode == RCODE.NXDOMAIN


def test_la_categoria_queda_registrada_al_bloquear(tmp_path):
    resolver = _resolver(tmp_path, "zero")
    _preguntar(resolver, "bloqueado.test")

    fila = resolver.logger_db.buscar()[0]
    assert fila["category"] == "publicidad"
    assert fila["blocked"] == 1


# ------------------------------------------------------ rendimiento


def test_la_latencia_separa_cache_de_internet(tmp_path):
    """Promediarlas juntas da un número que baja cuanto más caché tenés y que
    no sirve para detectar nada."""
    db = LoggerDB(str(tmp_path / "l.db"))
    db.log_query("1.1.1.1", "a.com", "A", False, source="upstream_primary_dot", duration_ms=100)
    db.log_query("1.1.1.1", "b.com", "A", False, source="upstream_primary_dot", duration_ms=200)
    db.log_query("1.1.1.1", "c.com", "A", False, source="cache", duration_ms=0.5)

    lat = db.latencia()

    assert lat["muestras"] == 2
    assert lat["promedio"] == pytest.approx(150.0)
    assert lat["minimo"] == pytest.approx(100.0)
    assert lat["maximo"] == pytest.approx(200.0)
    assert lat["cache_muestras"] == 1
    assert lat["cache_promedio"] == pytest.approx(0.5)


def test_la_latencia_ignora_mediciones_invalidas_y_anteriores_a_24_horas(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    db.log_query("1.1.1.1", "actual.com", "A", False,
                 source="upstream_primary_dot", duration_ms=100)
    db.log_query("1.1.1.1", "reloj-ajustado.com", "A", False,
                 source="upstream_primary_dot", duration_ms=-1200)
    db.log_query("1.1.1.1", "vieja.com", "A", False,
                 source="upstream_primary_dot", duration_ms=5000)
    with db._connect() as conn:
        conn.execute(
            "UPDATE queries SET timestamp = ? WHERE domain = ?",
            ("2000-01-01T00:00:00+00:00", "vieja.com"),
        )

    lat = db.latencia()

    assert lat["muestras"] == 1
    assert lat["promedio"] == pytest.approx(100.0)
    assert lat["minimo"] == pytest.approx(100.0)
    assert lat["maximo"] == pytest.approx(100.0)


def test_los_bloqueos_no_entran_en_el_promedio(tmp_path):
    """Responder un bloqueo es instantáneo y no sale a ningún lado: sumarlo al
    promedio de "cuánto tarda salir a internet" lo hunde y esconde el dato."""
    db = LoggerDB(str(tmp_path / "l.db"))
    db.log_query("1.1.1.1", "a.com", "A", False, source="upstream_primary_dot", duration_ms=100)
    for _ in range(50):
        db.log_query("1.1.1.1", "malo.com", "A", True, source="blocklist", duration_ms=0.1)

    assert db.latencia()["promedio"] == pytest.approx(100.0)


def test_los_upstream_caidos_tampoco_entran(tmp_path):
    """Una consulta que agotó el timeout de los dos upstreams mide el timeout,
    no la latencia de la red."""
    db = LoggerDB(str(tmp_path / "l.db"))
    db.log_query("1.1.1.1", "a.com", "A", False, source="upstream_primary_dot", duration_ms=50)
    db.log_query("1.1.1.1", "b.com", "A", False, source="error", duration_ms=4000)

    assert db.latencia()["promedio"] == pytest.approx(50.0)


def test_sin_consultas_salientes_no_se_inventa_un_promedio(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    db.log_query("1.1.1.1", "a.com", "A", False, source="cache", duration_ms=0.4)

    lat = db.latencia()
    assert lat["muestras"] == 0
    assert lat["promedio"] == 0.0


def test_bloqueos_por_categoria(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    for _ in range(5):
        db.log_query("1.1.1.1", "ads.com", "A", True, source="blocklist", category="publicidad")
    db.log_query("1.1.1.1", "mal.com", "A", True, source="blocklist", category="malware")
    db.log_query("1.1.1.1", "ok.com", "A", False, source="cache")

    assert db.bloqueos_por_categoria() == [("publicidad", 5), ("malware", 1)]


def test_un_bloqueo_sin_categoria_no_desaparece(tmp_path):
    """Las filas de una base vieja no tienen categoría. Tienen que seguir
    contándose, agrupadas en "amenaza", y no evaporarse del gráfico."""
    db = LoggerDB(str(tmp_path / "l.db"))
    db.log_query("1.1.1.1", "viejo.com", "A", True, source="blocklist")

    assert db.bloqueos_por_categoria() == [("amenaza", 1)]


def test_el_equipo_con_mas_bloqueos_no_es_el_que_mas_consulta(tmp_path):
    """Son dos preguntas distintas y por eso se muestran las dos: el que más
    consulta suele ser el que más se usa, el que más bloqueos junta es el que
    hay que ir a mirar."""
    db = LoggerDB(str(tmp_path / "l.db"))
    for _ in range(100):
        db.log_query("192.168.1.10", "trabajo.com", "A", False, source="cache")
    for _ in range(20):
        db.log_query("192.168.1.99", "malo.com", "A", True, source="blocklist", category="malware")

    por_total = db.top_clientes(ordenar_por="total")
    por_bloqueos = db.top_clientes(ordenar_por="bloqueadas")

    assert por_total[0][0] == "192.168.1.10"
    assert por_bloqueos[0][0] == "192.168.1.99"


# ------------------------------------------------- panel: detalle y exportar


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
        yield servidor.server_address[1], db
    finally:
        servidor.shutdown()


def _pedir(puerto, ruta) -> str:
    con = socket.create_connection(("127.0.0.1", puerto), timeout=5)
    try:
        con.sendall(
            f"GET {ruta} HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\n"
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


def test_el_detalle_viene_embebido_en_la_pagina(panel):
    """Va embebido en vez de pedirse al servidor al hacer clic: son 50 filas,
    pesa nada, y así abre al instante sin recargar ni perder la búsqueda."""
    puerto, db = panel
    db.log_query("192.168.1.7", "malo.test", "A", True, reason="dominio en blocklist: malo.test",
                 source="blocklist", duration_ms=0.3, category="malware")

    pagina = _pedir(puerto, "/")

    assert "verDetalle(" in pagina
    assert "Equipo que consultó" in pagina
    assert "192.168.1.7" in pagina
    assert "Malware" in pagina
    # El origen se traduce: "blocklist" a secas no se entiende en pantalla.
    assert "bloqueado por lista" in pagina


def test_exportar_csv_respeta_el_filtro(panel):
    """Lo que te llevás es lo que estás viendo. Exportar siempre todo obligaría
    a filtrar de nuevo afuera, que es el trabajo que el panel ya hizo."""
    puerto, db = panel
    db.log_query("192.168.1.7", "buscado.test", "A", False, source="cache")
    db.log_query("192.168.1.8", "otro.test", "A", False, source="cache")

    respuesta = _pedir(puerto, "/export.csv?q=buscado")

    assert "text/csv" in respuesta
    assert "buscado.test" in respuesta
    assert "otro.test" not in respuesta


def test_el_csv_trae_la_hora_local_y_no_utc(panel):
    """Un CSV que dice una hora distinta de la que viste en el panel es una
    trampa."""
    puerto, db = panel
    db.log_query("192.168.1.7", "algo.test", "A", True, source="blocklist")

    respuesta = _pedir(puerto, "/export.csv")

    cuerpo = respuesta.split("\r\n\r\n", 1)[1]
    fila = [linea for linea in cuerpo.splitlines() if "algo.test" in linea][0]
    # Formato dd/mm/aaaa hh:mm:ss, no ISO con zona horaria.
    assert "T" not in fila.split(",")[1]
    assert "/" in fila.split(",")[1]


def test_exportar_json_es_json_valido(panel):
    import json as _json

    puerto, db = panel
    db.log_query("192.168.1.7", "algo.test", "A", True, source="blocklist", category="malware")

    respuesta = _pedir(puerto, "/export.json")
    cuerpo = respuesta.split("\r\n\r\n", 1)[1]
    datos = _json.loads(cuerpo)

    assert datos[0]["domain"] == "algo.test"
    assert datos[0]["category"] == "malware"


def test_exportar_no_lo_puede_disparar_otra_pagina(panel):
    """Exportar no cambia nada, pero se lleva el historial de DNS entero de la
    casa. El chequeo de Host lo cubre igual que al resto del panel."""
    puerto, _db = panel
    con = socket.create_connection(("127.0.0.1", puerto), timeout=5)
    try:
        con.sendall(
            b"GET /export.csv HTTP/1.1\r\nHost: attacker.com\r\nConnection: close\r\n\r\n"
        )
        respuesta = con.recv(4096).decode("utf-8", "replace")
    finally:
        con.close()

    assert "403" in respuesta.split("\r\n")[0]


def test_el_panel_muestra_el_rendimiento(panel):
    puerto, db = panel
    db.log_query("192.168.1.7", "a.test", "A", False, source="upstream_primary_dot",
                 duration_ms=42)
    db.log_query("192.168.1.7", "b.test", "A", False, source="cache", duration_ms=0.3)

    pagina = _pedir(puerto, "/")

    assert "Rendimiento" in pagina
    assert "42 ms" in pagina
    assert "desde el caché" in pagina
