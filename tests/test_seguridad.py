"""Regresiones de la auditoría de cierre.

Cada test de acá corresponde a un agujero o a un bug que existía de verdad y
que se verificó antes de arreglarlo. El comentario de cada uno dice qué
pasaba, porque un test de seguridad sin esa explicación es un test que alguien
borra en seis meses por parecer redundante.
"""

import socket
import sys
import threading
import time
from pathlib import Path

import pytest
from dnslib import QTYPE, RR, A, DNSRecord

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns.blocklist import Allowlist, Blocklist  # noqa: E402
from securedns.dashboard import build_dashboard_server  # noqa: E402
from securedns.dns_server import MAX_TTL, ThreatIntelResolver  # noqa: E402
from securedns.logger_db import LoggerDB  # noqa: E402
from securedns.view_prefs import PreferenciasDeVista  # noqa: E402


def _resolver(tmp_path, **kw):
    (tmp_path / "bl.txt").write_text("", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    base = dict(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        logger_db=LoggerDB(str(tmp_path / "l.db")),
        upstream_primary="127.0.0.1", upstream_fallback="127.0.0.1",
        allowlist=Allowlist(str(tmp_path / "al.txt")),
    )
    base.update(kw)
    r = ThreatIntelResolver(**base)
    r.upstream_mode = "udp"
    return r


class _H:
    client_address = ("192.168.1.50", 5353)


# ------------------------------ envenenamiento de caché por UDP


def _respuesta(nombre, ident=None, qtype="A", ip="1.2.3.4", ttl=300):
    pedido = DNSRecord.question(nombre, qtype)
    if ident is not None:
        pedido.header.id = ident
    reply = pedido.reply()
    reply.add_answer(RR(nombre, QTYPE.A, rdata=A(ip), ttl=ttl))
    return reply


def test_se_descarta_una_respuesta_con_otro_id(tmp_path):
    """UDP no tiene sesión: sin validar el ID, cualquiera que meta un datagrama
    antes que el upstream se hace pasar por él, y esa respuesta forjada queda
    cacheada bajo la clave de la consulta legítima. Es envenenamiento de caché
    de manual."""
    resolver = _resolver(tmp_path)
    pedido = DNSRecord.question("banco.com")

    falsa = _respuesta("banco.com", ident=(pedido.header.id + 1) % 65536, ip="6.6.6.6")

    assert resolver._respuesta_valida(falsa.pack(), pedido) is False


def test_se_descarta_una_respuesta_de_otra_pregunta(tmp_path):
    """El otro lado del mismo ataque: acertar el ID pero contestar por un
    nombre distinto para envenenar ESE nombre."""
    resolver = _resolver(tmp_path)
    pedido = DNSRecord.question("banco.com")

    falsa = _respuesta("otra-cosa.com", ident=pedido.header.id)

    assert resolver._respuesta_valida(falsa.pack(), pedido) is False


def test_se_acepta_la_respuesta_correcta(tmp_path):
    resolver = _resolver(tmp_path)
    pedido = DNSRecord.question("banco.com")
    buena = _respuesta("banco.com", ident=pedido.header.id)

    assert resolver._respuesta_valida(buena.pack(), pedido) is True


def test_basura_no_lanza(tmp_path):
    resolver = _resolver(tmp_path)
    pedido = DNSRecord.question("banco.com")
    assert resolver._respuesta_valida(b"no soy dns", pedido) is False
    assert resolver._respuesta_valida(b"", pedido) is False


def test_el_ttl_tiene_techo(tmp_path):
    """Sin techo, una sola respuesta con el TTL máximo del protocolo deja el
    nombre apuntando adonde quiera el atacante durante 136 años, o sea hasta
    que alguien reinicie el proceso."""
    resolver = _resolver(tmp_path)
    resolver._forward_via_udp = lambda p: (
        _respuesta("eterno.com", ident=p.header.id, ttl=4294967295).pack(),
        "upstream_primary",
    )

    resolver.resolve(DNSRecord.question("eterno.com"), _H())

    _datos, vence = resolver._cache[("eterno.com", QTYPE.A)]
    assert vence - time.monotonic() <= MAX_TTL + 1


def test_una_respuesta_gigante_no_se_cachea(tmp_path):
    """Por TLS se pueden recibir hasta 64 KB por respuesta. Cacheando eso,
    20.000 entradas serían más de un giga de RAM."""
    resolver = _resolver(tmp_path)
    assert resolver.MAX_TAMANIO_RESPUESTA < 65536
    resolver._guardar_en_cache(("gigante.com", 1), b"x" * 60000, 300)
    assert resolver.cache_size() == 0


# ---------------------------------------- el cache bajo concurrencia


def test_el_cache_aguanta_muchos_hilos_a_la_vez(tmp_path):
    """Sin lock, la limpieza recorría el diccionario mientras otros hilos lo
    escribían y saltaba "dictionary changed size during iteration". Esa
    excepción no la atrapa dnslib, así que la consulta se quedaba SIN
    respuesta y el cliente esperaba hasta el timeout. Aparecía recién cuando el
    cache se llenaba, o sea justo cuando hay tráfico."""
    resolver = _resolver(tmp_path)
    resolver.MAX_CACHE = 200
    errores = []

    def machacar(inicio):
        try:
            for i in range(inicio, inicio + 500):
                resolver._guardar_en_cache((f"d{i}.com", 1), b"x", 300)
                resolver._leer_cache((f"d{i - 1}.com", 1))
                resolver.cache_size()
        except Exception as exc:  # noqa: BLE001
            errores.append(exc)

    hilos = [threading.Thread(target=machacar, args=(n * 1000,)) for n in range(8)]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()

    assert errores == []
    assert resolver.cache_size() <= 200


# ------------------------------------ bypass de las listas por normalización


def test_un_punto_final_en_el_feed_no_es_un_bypass(tmp_path):
    """Un atacante publica su URL con un punto final en el host
    ("http://banco-falso.com./login", que funciona igual en todos los
    navegadores), el feed lo indexa así, y esa entrada no matcheaba NUNCA
    ninguna consulta, porque del lado de la consulta el punto sí se saca."""
    (tmp_path / "f.txt").write_text("banco-falso.com.\n", encoding="utf-8")
    lista = Blocklist(str(tmp_path / "f.txt"))

    assert lista.is_blocked("banco-falso.com") is True
    assert lista.is_blocked("www.banco-falso.com") is True


def test_un_nombre_internacional_en_el_feed_tampoco(tmp_path):
    """Los feeds publican en Unicode y las consultas llegan en punycode."""
    (tmp_path / "f.txt").write_text("пример.com\n", encoding="utf-8")
    lista = Blocklist(str(tmp_path / "f.txt"))

    assert lista.is_blocked("xn--e1afmkfd.com") is True


# ------------------------------------------------- el panel


@pytest.fixture()
def panel(tmp_path):
    (tmp_path / "bl.txt").write_text("", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    (tmp_path / "ruido.txt").write_text("", encoding="utf-8")
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
        yield servidor.server_address[1], db, vista
    finally:
        servidor.shutdown()


def _crudo(puerto, ruta, host=None) -> str:
    con = socket.create_connection(("127.0.0.1", puerto), timeout=5)
    try:
        con.sendall(
            f"GET {ruta} HTTP/1.1\r\nHost: {host or f'127.0.0.1:{puerto}'}\r\n"
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


def test_ocultar_no_deja_meter_varias_lineas(panel):
    """`/ocultar` escribía tal cual lo que llegara. Un `domain=a.com%0Ab.com%0A...`
    metía varias líneas de una y sacaba del panel todos los dominios que
    quisiera quien lo mandara. No evita ningún bloqueo, porque este filtro es
    de vista, pero ciega al que está mirando, que es el complemento perfecto de
    una intrusión."""
    from urllib.parse import quote

    puerto, _db, vista = panel
    veneno = quote("bueno.com\nbanco.com\notro.com")

    _crudo(puerto, f"/ocultar?domain={veneno}")

    assert vista.dominios_manuales() == []


def test_la_api_no_filtra_detalles_internos_en_un_error(panel):
    """El texto de la excepción exponía rutas del filesystem y detalles del
    esquema a cualquier proceso local. Para diagnosticar está la consola del
    resolver, que es donde tiene que estar."""
    puerto, db, _vista = panel

    def explotar(*_a, **_k):
        raise RuntimeError("/ruta/secreta/del/servidor/dns_logs.db no existe")

    db.stats = explotar
    respuesta = _crudo(puerto, "/api/estadisticas")

    assert "500" in respuesta.split("\r\n")[0]
    assert "ruta/secreta" not in respuesta


def test_el_panel_responde_por_ipv6_local(panel):
    """El chequeo de Host sacaba el puerto contando los dos puntos, así que
    "[::1]:8890" nunca daba y el panel quedaba inalcanzable para quien entrara
    por IPv6."""
    puerto, _db, _vista = panel
    respuesta = _crudo(puerto, "/health", host="[::1]:8890")
    assert "200" in respuesta.split("\r\n")[0]


def test_las_opciones_del_filtro_van_escapadas(panel):
    """Era el único lugar del panel donde un dato de la base salía crudo al
    HTML. Hoy ninguno de los dos caminos que lo alimentan deja meter comillas,
    pero "hoy no se puede" es la clase de suposición que deja de valer cuando
    se agrega un feed nuevo."""
    puerto, db, _vista = panel
    db.log_query("1.1.1.1", "a.com", "A'><script>", False, source="cache")

    pagina = _crudo(puerto, "/")

    assert "<script>alert" not in pagina
    assert "&#x27;&gt;&lt;script&gt;" in pagina or "&lt;script&gt;" in pagina
