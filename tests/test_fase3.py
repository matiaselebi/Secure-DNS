"""Fase 3: DNSSEC, geolocalización de la respuesta y edad del dominio.

El hilo que une los tres: son datos que enriquecen lo que ya se registra, y
cada uno tiene un límite honesto que hay que respetar y que estos tests fijan.

- DNSSEC dice que **el upstream** validó, no que validamos nosotros.
- La geolocalización sale de una base local y nunca sale a la red.
- La edad por RDAP sí sale a la red y por eso viene apagada, se consulta solo
  para lo que ya llamó la atención, y falla hacia adelante.
"""

import socket
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from dnslib import QTYPE, RR, A, DNSRecord

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns.blocklist import Allowlist, Blocklist  # noqa: E402
from securedns.dashboard import build_dashboard_server  # noqa: E402
from securedns.dns_server import ThreatIntelResolver  # noqa: E402
from securedns.geoip import GeoIP  # noqa: E402
from securedns.logger_db import LoggerDB  # noqa: E402
from securedns.rdap import ClienteRDAP  # noqa: E402


# ------------------------------------------------------------ DNSSEC


def _resolver(tmp_path, **kw):
    (tmp_path / "bl.txt").write_text("bloqueado.test\n", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    base = dict(
        blocklist=Blocklist(str(tmp_path / "bl.txt")),
        logger_db=LoggerDB(str(tmp_path / "l.db")),
        upstream_primary="127.0.0.1", upstream_fallback="127.0.0.1",
        allowlist=Allowlist(str(tmp_path / "al.txt")),
    )
    base.update(kw)
    return ThreatIntelResolver(**base)


class _Handler:
    client_address = ("192.168.1.50", 5353)


def _respuesta_falsa(nombre, ip="93.184.216.34", ad=False):
    """Arma la respuesta que devolvería un upstream."""
    pedido = DNSRecord.question(nombre)
    reply = pedido.reply()
    reply.add_answer(RR(nombre, QTYPE.A, rdata=A(ip), ttl=300))
    reply.header.ad = 1 if ad else 0
    return reply.pack()


def test_se_le_pide_dnssec_al_upstream(tmp_path):
    """Sin el bit AD en el pedido, un resolver que valida no marca la respuesta
    como autenticada, y la estadística daría 0% para toda internet. Sería un
    número falso, no un número bajo."""
    resolver = _resolver(tmp_path)
    vistos = []

    def espiar(pedido):
        vistos.append(pedido.header.ad)
        return _respuesta_falsa("ejemplo.com", ad=True), "upstream_primary_dot"

    resolver._forward_via_udp = espiar
    resolver.upstream_mode = "udp"
    resolver.resolve(DNSRecord.question("ejemplo.com"), _Handler())

    assert vistos == [1]


def test_no_se_le_toca_el_pedido_original_al_cliente(tmp_path):
    """El mismo objeto se usa después para armar la respuesta: modificarlo
    sería cambiarle al cliente algo que no pidió."""
    resolver = _resolver(tmp_path)
    pedido = DNSRecord.question("ejemplo.com")
    resolver._forward_via_udp = lambda p: (_respuesta_falsa("ejemplo.com"), "upstream_primary")
    resolver.upstream_mode = "udp"

    resolver.resolve(pedido, _Handler())

    assert pedido.header.ad == 0


def test_se_registra_si_la_respuesta_venia_validada(tmp_path):
    resolver = _resolver(tmp_path)
    resolver.upstream_mode = "udp"
    resolver._forward_via_udp = lambda p: (
        _respuesta_falsa("firmado.test", ad=True), "upstream_primary"
    )
    resolver.resolve(DNSRecord.question("firmado.test"), _Handler())

    fila = resolver.logger_db.buscar(solo_bloqueadas=False)[0]
    assert fila["dnssec"] == 1


def test_los_bloqueos_no_cuentan_en_la_estadistica_de_dnssec(tmp_path):
    """Los bloqueos los responde este resolver y nunca están firmados. Meterlos
    en la cuenta hundiría el porcentaje sin que signifique nada."""
    db = LoggerDB(str(tmp_path / "l.db"))
    db.log_query("1.1.1.1", "a.com", "A", False, source="upstream_primary_dot", dnssec=1)
    for _ in range(50):
        db.log_query("1.1.1.1", "malo.com", "A", True, source="blocklist")

    datos = db.dnssec()
    assert datos["total"] == 1
    assert datos["porcentaje"] == pytest.approx(100.0)


def test_los_upstream_caidos_tampoco_cuentan(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    db.log_query("1.1.1.1", "a.com", "A", False, source="upstream_primary_dot", dnssec=1)
    db.log_query("1.1.1.1", "b.com", "A", False, source="error")

    assert db.dnssec()["total"] == 1


# ------------------------------------------------- geolocalización


def _base_geoip(tmp_path):
    """Base local mínima con un rango conocido."""
    import sqlite3

    ruta = tmp_path / "geo.db"
    # GeoIP solo crea el esquema si el archivo ya existe, justamente para poder
    # distinguir "no hay base" de "hay base vacía". Así que acá se arma a mano.
    with sqlite3.connect(ruta) as conn:
        conn.execute(
            "CREATE TABLE rangos (inicio INTEGER NOT NULL, fin INTEGER NOT NULL, "
            "pais TEXT, asn TEXT, proveedor TEXT)"
        )
        conn.execute("CREATE INDEX idx_rangos_inicio ON rangos (inicio)")
        # 93.184.216.0/24 en decimal.
        inicio = 93 * 256**3 + 184 * 256**2 + 216 * 256
        conn.execute(
            "INSERT INTO rangos (inicio, fin, pais, asn, proveedor) VALUES (?, ?, ?, ?, ?)",
            (inicio, inicio + 255, "US", "AS15133", "Edgecast"),
        )
        conn.commit()
    return GeoIP(str(ruta))


def test_la_ip_de_la_respuesta_queda_geolocalizada(tmp_path):
    """El resolver ya tiene la IP en la mano: geolocalizarla no cuesta una
    consulta extra ni sale a la red."""
    resolver = _resolver(tmp_path, geoip=_base_geoip(tmp_path))
    resolver.upstream_mode = "udp"
    resolver._forward_via_udp = lambda p: (
        _respuesta_falsa("ejemplo.com", ip="93.184.216.34"), "upstream_primary"
    )
    resolver.resolve(DNSRecord.question("ejemplo.com"), _Handler())

    fila = resolver.logger_db.buscar(solo_bloqueadas=False)[0]
    assert fila["dest_ip"] == "93.184.216.34"
    assert fila["country"] == "US"
    assert fila["asn"] == "AS15133"
    assert fila["provider"] == "Edgecast"


def test_sin_base_de_geolocalizacion_se_registra_igual(tmp_path):
    """Que falte la base no puede impedir que la consulta se registre."""
    resolver = _resolver(tmp_path, geoip=GeoIP(str(tmp_path / "no-existe.db")))
    resolver.upstream_mode = "udp"
    resolver._forward_via_udp = lambda p: (
        _respuesta_falsa("ejemplo.com"), "upstream_primary"
    )
    resolver.resolve(DNSRecord.question("ejemplo.com"), _Handler())

    fila = resolver.logger_db.buscar(solo_bloqueadas=False)[0]
    assert fila["dest_ip"] == "93.184.216.34"
    assert fila["country"] == ""


def test_los_paises_sin_dato_no_arman_un_desconocido_gigante(tmp_path):
    """Si la base no está descargada, la lista sale vacía en vez de inventar un
    "desconocido" que ocuparía el primer puesto y no diría nada."""
    db = LoggerDB(str(tmp_path / "l.db"))
    for _ in range(50):
        db.log_query("1.1.1.1", "a.com", "A", False, source="cache")
    db.log_query("1.1.1.1", "b.com", "A", False, source="cache", country="AR")

    assert db.top_paises() == [("AR", 1)]


# ----------------------------------------------------------- RDAP


def test_rdap_apagado_no_consulta_nada(tmp_path):
    """Viene apagado porque cada consulta le cuenta a un tercero qué dominio
    estás mirando, que es justo lo que DoT evita."""
    cliente = ClienteRDAP(False, str(tmp_path / "c.db"))
    llamadas = []
    cliente._consultar = lambda d: llamadas.append(d) or (None, "")

    assert cliente.edad("ejemplo.com") is None
    assert llamadas == []


def test_calcula_los_dias_desde_el_registro(tmp_path):
    cliente = ClienteRDAP(True, str(tmp_path / "c.db"))
    hace_diez = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    cliente._consultar = lambda d: (hace_diez, "")

    dato = cliente.edad("recien-registrado.com")

    assert dato["dias"] == 10
    assert dato["reciente"] is True


def test_un_dominio_viejo_no_se_marca(tmp_path):
    cliente = ClienteRDAP(True, str(tmp_path / "c.db"))
    hace_anios = (datetime.now(timezone.utc) - timedelta(days=4000)).isoformat()
    cliente._consultar = lambda d: (hace_anios, "")

    dato = cliente.edad("google.com")

    assert dato["dias"] == 4000
    assert dato["reciente"] is False


def test_no_se_pregunta_dos_veces_lo_mismo(tmp_path):
    """El cache dura 30 días porque la fecha de registro de un dominio no
    cambia."""
    cliente = ClienteRDAP(True, str(tmp_path / "c.db"))
    llamadas = []
    fecha = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()

    def contar(d):
        llamadas.append(d)
        return fecha, ""

    cliente._consultar = contar
    cliente.edad("ejemplo.com")
    cliente.edad("ejemplo.com")
    cliente.edad("ejemplo.com")

    assert len(llamadas) == 1


def test_sin_permiso_de_red_solo_se_mira_el_cache(tmp_path):
    """Es lo que usa el panel para no gastar el presupuesto de consultas."""
    cliente = ClienteRDAP(True, str(tmp_path / "c.db"))
    llamadas = []
    cliente._consultar = lambda d: llamadas.append(d) or (None, "")

    assert cliente.edad("ejemplo.com", permitir_red=False) is None
    assert llamadas == []


def test_un_tld_sin_rdap_no_rompe_nada(tmp_path):
    """Varios ccTLD no publican RDAP, incluido .ar. Eso no es un error: es una
    respuesta, y el panel muestra el hallazgo sin la edad."""
    cliente = ClienteRDAP(True, str(tmp_path / "c.db"))
    cliente._consultar = lambda d: (None, "el TLD no publica RDAP o el dominio no existe")

    assert cliente.edad("ejemplo.com.ar") is None


def test_el_servicio_caido_frena_los_intentos(tmp_path):
    """Sin freno, con RDAP caído cada refresco del panel se comería el timeout
    de cada dominio, uno por uno."""
    cliente = ClienteRDAP(True, str(tmp_path / "c.db"))
    llamadas = []

    def falla(d):
        llamadas.append(d)
        return None, "no se pudo consultar: ConnectionError"

    cliente._consultar = falla
    for i in range(10):
        cliente.edad(f"dominio{i}.com")

    # Tres fallos y se frena: el resto ni se intenta.
    assert len(llamadas) == 3


def test_una_fecha_ilegible_no_lanza(tmp_path):
    """Esto corre mientras se arma una página y no puede tumbarla."""
    cliente = ClienteRDAP(True, str(tmp_path / "c.db"))
    cliente._consultar = lambda d: ("no soy una fecha", "")

    assert cliente.edad("ejemplo.com") is None


def test_se_lee_el_evento_de_registro_y_no_el_primero():
    """RDAP devuelve varios eventos y el orden no está garantizado."""
    datos = {
        "events": [
            {"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"},
            {"eventAction": "registration", "eventDate": "2015-06-15T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2030-06-15T00:00:00Z"},
        ]
    }
    assert ClienteRDAP._fecha_de_registro(datos) == "2015-06-15T00:00:00Z"


# ------------------------------------------------------- el panel


@pytest.fixture()
def panel(tmp_path):
    (tmp_path / "bl.txt").write_text("", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    blocklist = Blocklist(str(tmp_path / "bl.txt"))
    allowlist = Allowlist(str(tmp_path / "al.txt"))
    db = LoggerDB(str(tmp_path / "l.db"))
    resolver = ThreatIntelResolver(
        blocklist=blocklist, logger_db=db,
        upstream_primary="127.0.0.1", upstream_fallback="127.0.0.1",
        allowlist=allowlist,
    )
    servidor = build_dashboard_server("127.0.0.1", 0, db, allowlist, blocklist, resolver)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield servidor.server_address[1], db
    finally:
        servidor.shutdown()


def _pedir(puerto, ruta="/") -> str:
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


def test_el_panel_aclara_quien_valido_la_firma(panel):
    """Decir "dominio firmado" a secas sería atribuirse un trabajo que hizo
    Quad9. Este proyecto no escribe criptografía propia."""
    puerto, db = panel
    db.log_query("1.1.1.1", "a.com", "A", False, source="upstream_primary_dot", dnssec=1)

    pagina = _pedir(puerto)

    assert "no que la validamos" in pagina
    assert "el upstream validó" in pagina


def test_el_detalle_muestra_la_geografia(panel):
    puerto, db = panel
    # El historial por defecto muestra los bloqueos, así que para que la fila
    # aparezca con su detalle se busca por el dominio.
    db.log_query("1.1.1.1", "geo.test", "A", False, source="upstream_primary_dot",
                 dest_ip="93.184.216.34", country="US", asn="AS15133", provider="Edgecast")

    pagina = _pedir(puerto, "/?q=geo.test")

    assert "93.184.216.34" in pagina
    assert "AS15133" in pagina
    assert "Edgecast" in pagina


def test_sin_base_el_panel_dice_como_conseguirla(panel):
    """Una sección vacía se lee como "esto no anda". Decir qué falta y cómo se
    consigue es información."""
    puerto, _db = panel
    pagina = _pedir(puerto)
    assert "update_geoip.py" in pagina
