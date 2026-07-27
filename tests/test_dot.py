"""Tests del modo DNS-over-TLS (DoT).

Estrategia en tres niveles, del más chico al más grande:

1. El framing TCP (prefijo de longitud de 2 bytes) se prueba con sockets
   locales comunes, sin TLS ni red: es lógica pura de bytes.
2. La orquestación (DoT primero, fallback a UDP según config) se prueba
   monkeypatcheando los métodos de transporte: lo que importa acá es QUÉ
   camino se elige, no cómo viaja.
3. Un test de integración real contra Quad9 por TLS, que se salta solo
   (skip) si la red donde corre el test bloquea el puerto 853 - así el
   suite nunca falla por culpa del firewall de la red, pero cuando puede,
   prueba el camino completo de verdad.
"""

import socket
import sys
import threading
from pathlib import Path

import pytest
from dnslib import QTYPE, RCODE, RR, A, DNSRecord

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns.blocklist import Blocklist  # noqa: E402
from securedns.dns_server import (  # noqa: E402
    ThreatIntelResolver,
    encode_tcp_query,
    read_tcp_response,
)
from securedns.logger_db import LoggerDB  # noqa: E402


def make_resolver(tmp_path, **kwargs):
    blocklist_path = tmp_path / "blocklist.txt"
    blocklist_path.write_text("")
    resolver = ThreatIntelResolver(
        blocklist=Blocklist(str(blocklist_path)),
        logger_db=LoggerDB(str(tmp_path / "logs.db")),
        upstream_primary=kwargs.pop("upstream_primary", "9.9.9.9"),
        upstream_fallback=kwargs.pop("upstream_fallback", "1.1.1.1"),
        **kwargs,
    )
    return resolver


class FakeHandler:
    client_address = ("127.0.0.1", 12345)


# ---------- 1) framing TCP ----------


def test_encode_tcp_query_prefixes_length_big_endian():
    payload = b"hola"
    framed = encode_tcp_query(payload)
    assert framed == b"\x00\x04hola"


def test_read_tcp_response_reassembles_fragmented_stream():
    """TCP puede entregar la respuesta en pedacitos; el lector tiene que
    rearmarla completa aunque llegue byte a byte."""
    server, client = socket.socketpair()
    payload = b"respuesta-dns-de-mentira"

    def drip_feed():
        framed = encode_tcp_query(payload)
        for i in range(len(framed)):
            server.sendall(framed[i : i + 1])
        server.close()

    thread = threading.Thread(target=drip_feed, daemon=True)
    thread.start()

    assert read_tcp_response(client) == payload
    thread.join(timeout=2)
    client.close()


def test_read_tcp_response_raises_if_connection_dies_midway():
    server, client = socket.socketpair()
    # Anuncia 100 bytes pero manda solo 3 y cierra: conexión rota a mitad de camino.
    server.sendall(b"\x00\x64abc")
    server.close()

    with pytest.raises(ConnectionError):
        read_tcp_response(client)
    client.close()


# ---------- 2) orquestación DoT / fallback UDP ----------


def canned_response_bytes(domain="example.com", ip="1.2.3.4"):
    reply = DNSRecord.question(domain).reply()
    reply.add_answer(RR(domain, QTYPE.A, rdata=A(ip), ttl=60))
    return reply.pack()


def test_dot_mode_uses_dot_and_not_udp(tmp_path, monkeypatch):
    resolver = make_resolver(tmp_path, upstream_mode="dot")
    canned = canned_response_bytes()
    called = {"udp": 0}

    monkeypatch.setattr(
        ThreatIntelResolver, "_forward_via_dot",
        lambda self, request: (canned, "upstream_primary_dot"),
    )

    def udp_spy(self, request):
        called["udp"] += 1
        return None, "error"

    monkeypatch.setattr(ThreatIntelResolver, "_forward_via_udp", udp_spy)

    reply = resolver.resolve(DNSRecord.question("example.com"), FakeHandler())

    assert reply.header.rcode == RCODE.NOERROR
    assert called["udp"] == 0  # nunca tocó el camino en texto plano


def test_dot_failure_falls_back_to_udp_when_allowed(tmp_path, monkeypatch):
    resolver = make_resolver(tmp_path, upstream_mode="dot", dot_fallback_to_udp=True)
    canned = canned_response_bytes()

    monkeypatch.setattr(
        ThreatIntelResolver, "_forward_via_dot", lambda self, request: (None, "error")
    )
    monkeypatch.setattr(
        ThreatIntelResolver, "_forward_via_udp",
        lambda self, request: (canned, "upstream_primary"),
    )

    reply = resolver.resolve(DNSRecord.question("example.com"), FakeHandler())

    assert reply.header.rcode == RCODE.NOERROR
    assert str(reply.rr[0].rdata) == "1.2.3.4"


def test_dot_failure_returns_servfail_when_fallback_disabled(tmp_path, monkeypatch):
    """Modo privacidad estricta: si TLS no anda y el fallback está apagado,
    se responde SERVFAIL antes que consultar en texto plano."""
    resolver = make_resolver(tmp_path, upstream_mode="dot", dot_fallback_to_udp=False)
    called = {"udp": 0}

    monkeypatch.setattr(
        ThreatIntelResolver, "_forward_via_dot", lambda self, request: (None, "error")
    )

    def udp_spy(self, request):
        called["udp"] += 1
        return canned_response_bytes(), "upstream_primary"

    monkeypatch.setattr(ThreatIntelResolver, "_forward_via_udp", udp_spy)

    reply = resolver.resolve(DNSRecord.question("example.com"), FakeHandler())

    assert reply.header.rcode == RCODE.SERVFAIL
    assert called["udp"] == 0


def test_udp_mode_never_touches_dot(tmp_path, monkeypatch):
    resolver = make_resolver(tmp_path, upstream_mode="udp")
    called = {"dot": 0}

    def dot_spy(self, request):
        called["dot"] += 1
        return None, "error"

    monkeypatch.setattr(ThreatIntelResolver, "_forward_via_dot", dot_spy)
    monkeypatch.setattr(
        ThreatIntelResolver, "_forward_via_udp",
        lambda self, request: (canned_response_bytes(), "upstream_primary"),
    )

    reply = resolver.resolve(DNSRecord.question("example.com"), FakeHandler())

    assert reply.header.rcode == RCODE.NOERROR
    assert called["dot"] == 0


def test_dot_retries_once_with_fresh_connection(tmp_path, monkeypatch):
    """Si la conexión TLS persistente murió (el upstream la cerró por
    inactividad), la primera escritura falla: debe descartarla y reintentar
    UNA vez con conexión nueva, sin propagar el error."""
    resolver = make_resolver(tmp_path, upstream_mode="dot")

    class DeadSocket:
        def sendall(self, data):
            raise ConnectionResetError("conexión cerrada por el upstream")

        def close(self):
            pass

    class LiveSocket:
        def __init__(self):
            self.buffer = b""

        def sendall(self, data):
            self.buffer += data

        def recv(self, n):
            # Devuelve una respuesta enlatada, con framing TCP.
            if not hasattr(self, "_out"):
                self._out = encode_tcp_query(b"pong")
            chunk, self._out = self._out[:n], self._out[n:]
            return chunk

        def close(self):
            pass

    resolver._dot_conns["9.9.9.9"] = DeadSocket()
    monkeypatch.setattr(
        ThreatIntelResolver, "_dot_connect", lambda self, ip, name: LiveSocket()
    )

    assert resolver._dot_query("9.9.9.9", "dns.quad9.net", b"ping") == b"pong"


# ---------- 3) TLS real contra un servidor DoT local ----------


def _openssl_available():
    import shutil

    return shutil.which("openssl") is not None


@pytest.mark.skipif(
    not _openssl_available(),
    reason="requiere el comando openssl para generar un certificado de prueba",
)
def test_dot_full_tls_roundtrip_against_local_server(tmp_path, monkeypatch):
    """Levanta un servidor DoT de mentira en localhost con TLS REAL
    (certificado autofirmado generado al vuelo) y hace una consulta
    completa a través de él. A diferencia de los tests de orquestación,
    acá el módulo ssl trabaja de verdad: handshake, validación de
    certificado contra una CA (la nuestra de prueba) y framing sobre el
    stream cifrado. Sin depender de internet."""
    import ssl as ssl_mod
    import subprocess

    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True, capture_output=True,
    )

    server_ctx = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(cert), str(key))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    canned = canned_response_bytes("example.com", "5.6.7.8")

    def serve_one():
        conn, _ = listener.accept()
        tls_conn = server_ctx.wrap_socket(conn, server_side=True)
        request_bytes = read_tcp_response(tls_conn)  # mismo framing en ambas direcciones
        assert DNSRecord.parse(request_bytes).q.qname  # llegó una consulta DNS válida
        tls_conn.sendall(encode_tcp_query(canned))
        tls_conn.close()

    thread = threading.Thread(target=serve_one, daemon=True)
    thread.start()

    resolver = make_resolver(
        tmp_path,
        upstream_mode="dot",
        dot_fallback_to_udp=False,
        upstream_primary="127.0.0.1",
        upstream_primary_tls_name="localhost",
    )
    # El cliente valida certificados contra su lista de CAs; para el test, la
    # única CA confiable es nuestro certificado autofirmado recién creado.
    client_ctx = ssl_mod.create_default_context(cafile=str(cert))
    resolver._tls_context = client_ctx
    # El puerto 853 real no se puede usar sin root; apuntamos al efímero.
    import securedns.dns_server as dns_server_mod

    monkeypatch.setattr(dns_server_mod, "DOT_PORT", port)

    data, label = resolver._forward_via_dot(DNSRecord.question("example.com"))

    thread.join(timeout=3)
    listener.close()

    assert label == "upstream_primary_dot"
    reply = DNSRecord.parse(data)
    assert str(reply.rr[0].rdata) == "5.6.7.8"


# ---------- 4) integración real contra Quad9 (se salta sin red/853) ----------


def _dot_reachable(ip="9.9.9.9", timeout=3.0):
    try:
        socket.create_connection((ip, 853), timeout=timeout).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(
    not _dot_reachable(),
    reason="el puerto 853 hacia Quad9 no es alcanzable desde esta red",
)
def test_live_dot_query_against_quad9(tmp_path):
    resolver = make_resolver(tmp_path, upstream_mode="dot", dot_fallback_to_udp=False)

    reply = resolver.resolve(DNSRecord.question("example.com"), FakeHandler())

    assert reply.header.rcode == RCODE.NOERROR
    assert len(reply.rr) >= 1
