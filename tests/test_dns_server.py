import socket
import sys
import threading
import time
from pathlib import Path

import pytest
from dnslib import QTYPE, RCODE, RR, A, DNSRecord

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns.blocklist import Allowlist, Blocklist  # noqa: E402
from securedns import dns_server as dns_server_module  # noqa: E402
from securedns.dns_server import ThreatIntelResolver, build_dns_server  # noqa: E402
from securedns.logger_db import LoggerDB  # noqa: E402


class FakeHandler:
    """dnslib le pasa un 'handler' con client_address a resolve(); acá lo
    simulamos sin levantar un servidor real para los tests unitarios."""

    def __init__(self, client_ip="127.0.0.1"):
        self.client_address = (client_ip, 12345)


def make_resolver(tmp_path, blocked_domains=None, **kwargs):
    blocklist_path = tmp_path / "blocklist.txt"
    blocklist_path.write_text("\n".join(blocked_domains or []))
    blocklist = Blocklist(str(blocklist_path))
    logger_db = LoggerDB(str(tmp_path / "logs.db"))
    resolver = ThreatIntelResolver(
        blocklist=blocklist,
        logger_db=logger_db,
        upstream_primary=kwargs.get("upstream_primary", "9.9.9.9"),
        upstream_fallback=kwargs.get("upstream_fallback", "1.1.1.1"),
        upstream_timeout=kwargs.get("upstream_timeout", 2.0),
        min_cache_ttl=kwargs.get("min_cache_ttl", 30),
    )
    return resolver, logger_db


def test_blocks_domain_in_blocklist(tmp_path):
    resolver, logger_db = make_resolver(tmp_path, blocked_domains=["malicious-example.com"])

    request = DNSRecord.question("malicious-example.com")
    reply = resolver.resolve(request, FakeHandler())

    assert reply.header.rcode == RCODE.NXDOMAIN
    stats = logger_db.stats()
    assert stats["total_queries"] == 1
    assert stats["blocked_queries"] == 1


def test_allowlist_wins_over_blocklist(tmp_path, monkeypatch):
    """Un dominio en la allowlist debe resolverse normalmente (no NXDOMAIN)
    aunque también figure en la blocklist."""
    blocklist_path = tmp_path / "blocklist.txt"
    blocklist_path.write_text("shared-domain.com\n")
    blocklist = Blocklist(str(blocklist_path))

    allowlist_path = tmp_path / "allowlist.txt"
    allowlist_path.write_text("shared-domain.com\n")
    allowlist = Allowlist(str(allowlist_path))

    logger_db = LoggerDB(str(tmp_path / "logs.db"))
    resolver = ThreatIntelResolver(
        blocklist=blocklist,
        logger_db=logger_db,
        upstream_primary="9.9.9.9",
        upstream_fallback="1.1.1.1",
        allowlist=allowlist,
    )

    canned_request = DNSRecord.question("shared-domain.com")
    canned_reply = canned_request.reply()
    canned_reply.add_answer(RR("shared-domain.com", QTYPE.A, rdata=A("1.2.3.4"), ttl=60))
    canned_bytes = canned_reply.pack()

    monkeypatch.setattr(
        ThreatIntelResolver, "_forward_to_upstream", lambda self, request: (canned_bytes, "upstream_primary")
    )

    request = DNSRecord.question("shared-domain.com")
    reply = resolver.resolve(request, FakeHandler())

    assert reply.header.rcode == RCODE.NOERROR
    assert str(reply.rr[0].rdata) == "1.2.3.4"

    stats = logger_db.stats()
    assert stats["blocked_queries"] == 0


def test_clear_cache_empties_response_cache(tmp_path):
    resolver, _ = make_resolver(tmp_path, blocked_domains=[])

    resolver._cache[("example.com", 1)] = (b"fake-response", 9999999999.0)
    assert resolver.cache_size() == 1

    resolver.clear_cache()

    assert resolver.cache_size() == 0


def test_forwards_to_upstream_and_caches(tmp_path, monkeypatch):
    resolver, logger_db = make_resolver(tmp_path, blocked_domains=[])

    canned_request = DNSRecord.question("example.com")
    canned_reply = canned_request.reply()
    canned_reply.add_answer(RR("example.com", QTYPE.A, rdata=A("93.184.216.34"), ttl=300))
    canned_bytes = canned_reply.pack()

    call_count = {"n": 0}

    def fake_forward(self, request):
        call_count["n"] += 1
        return canned_bytes, "upstream_primary"

    monkeypatch.setattr(ThreatIntelResolver, "_forward_to_upstream", fake_forward)

    request = DNSRecord.question("example.com")
    reply1 = resolver.resolve(request, FakeHandler())
    reply2 = resolver.resolve(DNSRecord.question("example.com"), FakeHandler())

    assert reply1.header.rcode == RCODE.NOERROR
    assert str(reply1.rr[0].rdata) == "93.184.216.34"
    # La segunda consulta debería resolverse desde caché, sin volver a "salir" upstream.
    assert call_count["n"] == 1

    stats = logger_db.stats()
    assert stats["total_queries"] == 2
    assert stats["cached_queries"] == 1


def test_la_duracion_no_depende_del_reloj_de_pared(tmp_path, monkeypatch):
    resolver, logger_db = make_resolver(tmp_path, blocked_domains=[])
    request = DNSRecord.question("example.com")
    reply = request.reply()
    reply.add_answer(RR("example.com", QTYPE.A, rdata=A("1.2.3.4"), ttl=60))

    class RelojMonotono:
        pasos = iter((10.0, 10.01))

        @classmethod
        def perf_counter(cls):
            return next(cls.pasos)

        @staticmethod
        def monotonic():
            return 1000.0

    monkeypatch.setattr(dns_server_module, "time", RelojMonotono)
    monkeypatch.setattr(
        ThreatIntelResolver, "_forward_to_upstream",
        lambda self, pedido: (reply.pack(), "upstream_primary_dot"),
    )

    resolver.resolve(request, FakeHandler())

    assert logger_db.buscar(solo_bloqueadas=False)[0]["duration_ms"] == pytest.approx(10.0)


def test_upstream_fallback_when_primary_unreachable(tmp_path):
    """El primario apunta a una IP que no responde (timeout corto); el
    resolver debe caer al de respaldo, que sí contesta."""

    # Servidor UDP de mentira que simula el resolver de respaldo (Cloudflare/Quad9 reales).
    fake_upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fake_upstream.bind(("127.0.0.1", 0))
    fake_upstream_port = fake_upstream.getsockname()[1]

    def serve_one_fake_response():
        data, addr = fake_upstream.recvfrom(512)
        req = DNSRecord.parse(data)
        reply = req.reply()
        reply.add_answer(RR("example.com", QTYPE.A, rdata=A("1.2.3.4"), ttl=60))
        fake_upstream.sendto(reply.pack(), addr)

    thread = threading.Thread(target=serve_one_fake_response, daemon=True)
    thread.start()

    resolver, logger_db = make_resolver(
        tmp_path,
        blocked_domains=[],
        upstream_primary="127.0.0.1",  # ver override de puerto abajo: no hay nadie escuchando
        upstream_fallback="127.0.0.1",
        upstream_timeout=0.3,
    )
    # _forward_to_upstream usa siempre el puerto 53 del upstream, pero en el
    # test necesitamos puertos efímeros propios (no podemos bindear el 53 sin
    # ser root, ni depender de que 53 esté libre). Parcheamos el método para
    # que el "primario" apunte a un puerto que nadie escucha (falla seguro,
    # sin depender de la red real) y el "de respaldo" a nuestro servidor de
    # mentira de arriba.
    original_forward = ThreatIntelResolver._forward_to_upstream

    def patched_forward(self, request):
        for upstream, port, label in (
            (self.upstream_primary, 1, "upstream_primary"),  # puerto 1: nadie escucha ahí
            (self.upstream_fallback, fake_upstream_port, "upstream_fallback"),
        ):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.upstream_timeout)
                sock.sendto(request.pack(), (upstream, port))
                data, _ = sock.recvfrom(4096)
                return data, label
            except OSError:
                continue
            finally:
                sock.close()
        return None, "error"

    resolver._forward_to_upstream = patched_forward.__get__(resolver, ThreatIntelResolver)

    request = DNSRecord.question("example.com")
    reply = resolver.resolve(request, FakeHandler())

    thread.join(timeout=2)
    fake_upstream.close()

    assert reply.header.rcode == RCODE.NOERROR
    assert str(reply.rr[0].rdata) == "1.2.3.4"


def test_dashboard_and_dns_integration(tmp_path):
    """Levanta el resolver DNS real en un puerto efímero y confirma que
    bloquea un dominio de la lista end-to-end, por UDP de verdad."""
    resolver, logger_db = make_resolver(tmp_path, blocked_domains=["malicious-example.com"])
    server = build_dns_server("127.0.0.1", 0, resolver)
    server.start_thread()
    time.sleep(0.2)

    port = server.server.server_address[1]
    request = DNSRecord.question("malicious-example.com")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(request.pack(), ("127.0.0.1", port))
    data, _ = sock.recvfrom(512)
    reply = DNSRecord.parse(data)

    server.stop()

    assert reply.header.rcode == RCODE.NXDOMAIN
