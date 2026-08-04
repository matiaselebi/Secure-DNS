"""Marcar un hallazgo de detección como normal.

El detector de tunneling mira la forma del tráfico, así que un CDN de video le
da la razón: `rr3---sn-4g5e6nz7.googlevideo.com` es un nombre distinto por
servidor, largo y sin forma de palabra. Dos señales de cinco, que es el mínimo
para marcar. Estos tests cubren que se pueda cerrar ese hallazgo a mano, que
cerrarlo devuelva los puntos, y sobre todo que NO se convierta en una lista
blanca por accidente.
"""

import socket
import sys
import threading
import time
from pathlib import Path
from urllib.parse import quote

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns import puntaje  # noqa: E402
from securedns.blocklist import Allowlist, Blocklist  # noqa: E402
from securedns.dashboard import build_dashboard_server  # noqa: E402
from securedns.dns_server import ThreatIntelResolver  # noqa: E402
from securedns.hallazgos import HallazgosNormales  # noqa: E402
from securedns.logger_db import LoggerDB  # noqa: E402


# ------------------------------------------------------------ la lista sola


def test_cubre_los_subdominios(tmp_path):
    n = HallazgosNormales(str(tmp_path / "n.txt"))
    n.marcar("googlevideo.com")
    assert n.es_normal("googlevideo.com")
    assert n.es_normal("rr3---sn-4g5e6nz7.googlevideo.com")
    assert not n.es_normal("googlevideo.com.attacker.net")


def test_el_punto_final_no_es_un_bypass(tmp_path):
    """Mismo agujero que ya había en las otras listas: si la entrada se
    guardara cruda, "googlevideo.com." nunca matchearía."""
    n = HallazgosNormales(str(tmp_path / "n.txt"))
    n.marcar("googlevideo.com.")
    assert n.es_normal("googlevideo.com")


def test_se_puede_revertir(tmp_path):
    n = HallazgosNormales(str(tmp_path / "n.txt"))
    n.marcar("googlevideo.com")
    n.volver_a_vigilar("googlevideo.com")
    assert not n.es_normal("googlevideo.com")
    assert n.marcados() == []


def test_sin_archivo_no_silencia_nada(tmp_path):
    n = HallazgosNormales(None)
    assert not n.es_normal("lo-que-sea.com")
    assert n.filtrar([{"padre": "lo-que-sea.com"}]) == [{"padre": "lo-que-sea.com"}]


def test_filtrar_saca_solo_los_marcados(tmp_path):
    n = HallazgosNormales(str(tmp_path / "n.txt"))
    n.marcar("googlevideo.com")
    grupos = [{"padre": "googlevideo.com"}, {"padre": "tunel.atacante.com"}]
    assert n.filtrar(grupos) == [{"padre": "tunel.atacante.com"}]


# ------------------------------------------------------------ el puntaje


def test_marcar_devuelve_los_puntos():
    """El descuento de tunneling son 20 puntos. Si marcar el hallazgo no los
    devolviera, el puntaje quedaría en 80 sin nada visible que lo explique, y
    un número que no se puede rastrear hasta su causa es justo lo que este
    puntaje promete no ser."""
    base = {"modo_upstream": "dot", "respaldo_sin_cifrar": False}
    con_hallazgo = puntaje.calcular(
        dict(base, tunneling=[{"padre": "googlevideo.com", "cliente": "127.0.0.1"}])
    )
    sin_hallazgo = puntaje.calcular(dict(base, tunneling=[]))
    assert sin_hallazgo["puntaje"] == 100
    assert sin_hallazgo["puntaje"] - con_hallazgo["puntaje"] == puntaje.PESOS["tunneling"]


# ------------------------------------------------------------ el panel


def _armar(tmp_path):
    for nombre in ("bl.txt", "al.txt"):
        (tmp_path / nombre).write_text("", encoding="utf-8")
    blocklist = Blocklist(str(tmp_path / "bl.txt"))
    allowlist = Allowlist(str(tmp_path / "al.txt"))
    db = LoggerDB(str(tmp_path / "l.db"))
    resolver = ThreatIntelResolver(
        blocklist=blocklist, logger_db=db,
        upstream_primary="127.0.0.1", upstream_fallback="127.0.0.1",
        allowlist=allowlist,
    )
    normales = HallazgosNormales(str(tmp_path / "n.txt"))
    servidor = build_dashboard_server(
        "127.0.0.1", 0, db, allowlist, blocklist, resolver, normales=normales,
    )
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return servidor, normales, blocklist, allowlist


@pytest.fixture()
def panel(tmp_path):
    servidor, normales, blocklist, allowlist = _armar(tmp_path)
    try:
        yield servidor.server_address[1], normales, blocklist, allowlist
    finally:
        servidor.shutdown()


def _pedir(puerto, ruta, extra=""):
    con = socket.create_connection(("127.0.0.1", puerto), timeout=5)
    try:
        con.sendall(
            f"GET {ruta} HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\n{extra}"
            "Connection: close\r\n\r\n".encode()
        )
        con.settimeout(5)
        datos = b""
        try:
            while len(datos) < 2_000_000:
                trozo = con.recv(8192)
                if not trozo:
                    break
                datos += trozo
        except socket.timeout:
            pass
        return datos.decode("utf-8", "replace")
    finally:
        con.close()


def test_marcar_desde_el_panel(panel):
    puerto, normales, _bl, _al = panel
    _pedir(puerto, "/normal?domain=googlevideo.com")
    assert normales.es_normal("googlevideo.com")
    _pedir(puerto, "/vigilar?domain=googlevideo.com")
    assert not normales.es_normal("googlevideo.com")


def test_marcar_no_es_permitir(panel):
    """Lo más importante del módulo. Si marcar un hallazgo tocara la lista
    blanca, un atacante que consiga que marques su dominio (o vos mismo
    cerrando un aviso apurado) desactivaría el filtrado para ese dominio para
    siempre, que es lo contrario de lo que dice el botón."""
    puerto, _normales, blocklist, allowlist = panel

    _pedir(puerto, "/normal?domain=tunel.atacante.com")

    assert allowlist.manual_entries() == []
    assert blocklist.manual_entries() == []
    assert not allowlist.is_allowed("tunel.atacante.com")


def test_una_web_cualquiera_no_puede_silenciar_detecciones(panel):
    """CSRF. Silenciar hallazgos desde afuera es el paso previo perfecto a una
    intrusión: no desbloquea nada, pero ciega al que está mirando."""
    puerto, normales, _bl, _al = panel

    respuesta = _pedir(
        puerto, "/normal?domain=tunel.atacante.com",
        extra="Sec-Fetch-Site: cross-site\r\nOrigin: https://sitio-malicioso.com\r\n",
    )

    assert "403" in respuesta.split("\r\n")[0]
    assert normales.marcados() == []


def test_no_deja_meter_varias_lineas(panel):
    puerto, normales, _bl, _al = panel
    veneno = quote("a.com\nb.com\nc.com")
    _pedir(puerto, f"/normal?domain={veneno}")
    assert normales.marcados() == []


def test_lo_marcado_se_ve_y_se_puede_revertir(panel):
    """Silenciar sin poder ver qué silenciaste es cómo un panel termina en
    verde por decisiones que nadie recuerda haber tomado."""
    puerto, _normales, _bl, _al = panel
    _pedir(puerto, "/normal?domain=googlevideo.com")

    pagina = _pedir(puerto, "/")

    assert "Marcados como normales" in pagina
    assert "googlevideo.com" in pagina
    assert "/vigilar?domain=googlevideo.com" in pagina
