"""Resolver DNS con filtrado por lista negra, caché por TTL, y reenvío a
servidores upstream (con respaldo si el principal no responde).

El reenvío upstream soporta dos modos:

- "dot" (DNS-over-TLS, el default): la consulta viaja cifrada por TLS al
  puerto 853 del upstream. Tu ISP (o cualquiera en el medio) ya no puede
  leer qué dominios consultás. Se implementa solo con `ssl` y `socket` de
  la librería estándar: cero dependencias nuevas, y cero criptografía
  propia (el TLS lo hace la librería estándar de Python contra los
  certificados reales de Quad9/Cloudflare).
- "udp" (texto plano, puerto 53): el modo clásico, que queda como respaldo
  automático si el puerto 853 está bloqueado en tu red (configurable).
"""

import socket
import ssl
import threading
import time

from dnslib import QTYPE, RCODE, DNSRecord
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from .blocklist import Allowlist, Blocklist
from .logger_db import LoggerDB

# Silencia el logging a stdout que trae dnslib por defecto (ya logueamos
# nosotros mismos a SQLite, con más detalle y de forma consultable).
_QUIET_LOGGER = DNSLogger(log="-request,-reply,-truncated,-error", prefix=False)

DOT_PORT = 853


def encode_tcp_query(payload: bytes) -> bytes:
    """DNS sobre TCP/TLS antepone la longitud del mensaje en 2 bytes
    (big-endian), porque TCP es un stream continuo y el receptor necesita
    saber dónde termina cada mensaje (en UDP no hace falta: 1 datagrama =
    1 mensaje). RFC 1035, sección 4.2.2."""
    return len(payload).to_bytes(2, "big") + payload


def read_tcp_response(sock) -> bytes:
    """Lee una respuesta DNS con prefijo de longitud desde un socket
    TCP/TLS, en un loop porque un recv() puede devolver menos bytes de los
    pedidos (así funciona TCP; con UDP esto no pasa)."""
    header = _read_exactly(sock, 2)
    length = int.from_bytes(header, "big")
    return _read_exactly(sock, length)


def _read_exactly(sock, n: int) -> bytes:
    chunks = b""
    while len(chunks) < n:
        chunk = sock.recv(n - len(chunks))
        if not chunk:
            raise ConnectionError("el upstream cerró la conexión a mitad de una respuesta")
        chunks += chunk
    return chunks


class ThreatIntelResolver(BaseResolver):
    """Decide, para cada consulta DNS entrante, si se bloquea, se responde
    desde caché, o se reenvía a un servidor upstream (con respaldo)."""

    def __init__(
        self,
        blocklist: Blocklist,
        logger_db: LoggerDB,
        upstream_primary: str,
        upstream_fallback: str,
        upstream_timeout: float = 2.0,
        min_cache_ttl: int = 30,
        allowlist: Allowlist | None = None,
        upstream_mode: str = "udp",
        upstream_primary_tls_name: str = "dns.quad9.net",
        upstream_fallback_tls_name: str = "cloudflare-dns.com",
        dot_fallback_to_udp: bool = True,
    ):
        self.blocklist = blocklist
        self.logger_db = logger_db
        self.upstream_primary = upstream_primary
        self.upstream_fallback = upstream_fallback
        self.upstream_timeout = upstream_timeout
        self.min_cache_ttl = min_cache_ttl
        self.allowlist = allowlist
        self.upstream_mode = upstream_mode
        self.upstream_primary_tls_name = upstream_primary_tls_name
        self.upstream_fallback_tls_name = upstream_fallback_tls_name
        self.dot_fallback_to_udp = dot_fallback_to_udp
        # cache_key -> (respuesta empaquetada sin el id, timestamp de vencimiento)
        self._cache: dict[tuple[str, int], tuple[bytes, float]] = {}
        # Conexiones TLS persistentes por IP de upstream: el handshake TLS
        # cuesta ~1 ida y vuelta extra, así que en vez de pagarlo en cada
        # consulta, se mantiene la conexión abierta y se reusa. El lock evita
        # que dos consultas concurrentes escriban mezclado en el mismo socket.
        self._dot_conns: dict[str, ssl.SSLSocket] = {}
        self._dot_lock = threading.Lock()
        # create_default_context() valida el certificado del upstream contra
        # las CAs del sistema y chequea que el nombre coincida (server_hostname):
        # exactamente lo que un cliente TLS bien hecho debe hacer.
        self._tls_context = ssl.create_default_context()

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        start = time.time()
        qname = str(request.q.qname).rstrip(".").lower()
        qtype_id = request.q.qtype
        qtype_name = QTYPE.get(qtype_id, str(qtype_id))
        client_ip = handler.client_address[0] if hasattr(handler, "client_address") else "-"

        # La allowlist gana por sobre la blocklist: si el dominio está acá,
        # ni siquiera se evalúa el resto y se pasa directo a resolver/cachear.
        if self.allowlist is not None and self.allowlist.is_allowed(qname):
            pass
        elif self.blocklist.is_blocked(qname):
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            duration_ms = (time.time() - start) * 1000
            self.logger_db.log_query(
                client_ip, qname, qtype_name, True,
                reason=f"dominio en blocklist: {qname}", source="blocklist",
                duration_ms=duration_ms,
            )
            return reply

        cache_key = (qname, qtype_id)
        cached = self._cache.get(cache_key)
        if cached and time.time() < cached[1]:
            reply = DNSRecord.parse(cached[0])
            reply.header.id = request.header.id
            duration_ms = (time.time() - start) * 1000
            self.logger_db.log_query(
                client_ip, qname, qtype_name, False, source="cache", duration_ms=duration_ms,
            )
            return reply

        response_bytes, source = self._forward_to_upstream(request)
        duration_ms = (time.time() - start) * 1000

        if response_bytes is None:
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            self.logger_db.log_query(
                client_ip, qname, qtype_name, False,
                reason="ningún servidor upstream respondió", source="error",
                duration_ms=duration_ms,
            )
            return reply

        reply = DNSRecord.parse(response_bytes)
        ttl = max((rr.ttl for rr in reply.rr), default=self.min_cache_ttl)
        ttl = max(ttl, self.min_cache_ttl)
        self._cache[cache_key] = (response_bytes, time.time() + ttl)

        self.logger_db.log_query(
            client_ip, qname, qtype_name, False, source=source, duration_ms=duration_ms,
        )
        return reply

    def clear_cache(self) -> None:
        """Vacía el cache de respuestas en memoria. Pensado para el botón
        "Borrar cache" del dashboard/menú .bat: la próxima consulta de
        cualquier dominio se vuelve a pedir a upstream en vez de servirse
        desde una respuesta guardada."""
        self._cache.clear()

    def cache_size(self) -> int:
        return len(self._cache)

    def _forward_to_upstream(self, request: DNSRecord) -> tuple[bytes | None, str]:
        """Orquesta el reenvío según el modo configurado: primero DoT (si
        corresponde), y si ningún upstream respondió por TLS, cae a UDP en
        texto plano - solo si `dot_fallback_to_udp` lo permite. La idea:
        mejor una consulta en texto plano que quedarse sin internet en una
        red que bloquea el puerto 853 (cafés, universidades, etc.)."""
        if self.upstream_mode == "dot":
            data, label = self._forward_via_dot(request)
            if data is not None:
                return data, label
            if not self.dot_fallback_to_udp:
                return None, "error"
        return self._forward_via_udp(request)

    def _forward_via_udp(self, request: DNSRecord) -> tuple[bytes | None, str]:
        """Modo clásico: intenta el servidor primario y, si falla, el de
        respaldo. Texto plano por UDP al puerto 53."""
        for upstream, label in (
            (self.upstream_primary, "upstream_primary"),
            (self.upstream_fallback, "upstream_fallback"),
        ):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.upstream_timeout)
                sock.sendto(request.pack(), (upstream, 53))
                data, _ = sock.recvfrom(4096)
                return data, label
            except OSError:
                continue
            finally:
                sock.close()
        return None, "error"

    def _forward_via_dot(self, request: DNSRecord) -> tuple[bytes | None, str]:
        """DNS-over-TLS: igual que el modo UDP (primario, y respaldo si
        falla), pero cifrado por TLS al puerto 853."""
        for upstream, tls_name, label in (
            (self.upstream_primary, self.upstream_primary_tls_name, "upstream_primary_dot"),
            (self.upstream_fallback, self.upstream_fallback_tls_name, "upstream_fallback_dot"),
        ):
            try:
                return self._dot_query(upstream, tls_name, request.pack()), label
            except (OSError, ssl.SSLError, ConnectionError):
                continue
        return None, "error"

    def _dot_query(self, upstream_ip: str, tls_name: str, payload: bytes) -> bytes:
        """Manda una consulta por la conexión TLS persistente hacia ese
        upstream (abriéndola si no existe). Si la conexión guardada murió
        (el upstream cierra conexiones inactivas después de un rato), se
        descarta y se reintenta UNA vez con una conexión nueva."""
        with self._dot_lock:
            for attempt in (1, 2):
                sock = self._dot_conns.get(upstream_ip)
                if sock is None:
                    sock = self._dot_connect(upstream_ip, tls_name)
                    self._dot_conns[upstream_ip] = sock
                try:
                    sock.sendall(encode_tcp_query(payload))
                    return read_tcp_response(sock)
                except (OSError, ssl.SSLError, ConnectionError):
                    self._dot_close(upstream_ip)
                    if attempt == 2:
                        raise
            raise ConnectionError("inalcanzable")  # nunca llega; para el type checker

    def _dot_connect(self, upstream_ip: str, tls_name: str) -> ssl.SSLSocket:
        raw_sock = socket.create_connection((upstream_ip, DOT_PORT), timeout=self.upstream_timeout)
        # server_hostname cumple doble función: SNI (le dice al servidor qué
        # certificado presentar) y validación (si el certificado no es
        # realmente de dns.quad9.net, el handshake falla acá mismo).
        return self._tls_context.wrap_socket(raw_sock, server_hostname=tls_name)

    def _dot_close(self, upstream_ip: str) -> None:
        sock = self._dot_conns.pop(upstream_ip, None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def build_dns_server(
    host: str,
    port: int,
    resolver: ThreatIntelResolver,
) -> DNSServer:
    return DNSServer(resolver, address=host, port=port, logger=_QUIET_LOGGER)
