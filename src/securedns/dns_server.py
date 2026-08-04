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

from dnslib import AAAA, QTYPE, RCODE, RR, A, DNSRecord
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from .blocklist import Allowlist, Blocklist
from .logger_db import LoggerDB
from .validation import normalizar_nombre_consultado

# Silencia el logging a stdout que trae dnslib por defecto (ya logueamos
# nosotros mismos a SQLite, con más detalle y de forma consultable).
_QUIET_LOGGER = DNSLogger(log="-request,-reply,-truncated,-error", prefix=False)

DOT_PORT = 853

# Nombres EXACTOS de los que depende el propio resolver para funcionar.
#
# Qué arregla: si SecureDNS es el DNS del sistema, todo lo que el resolver
# consulta hacia afuera (los feeds de amenazas, RDAP, las alertas de Telegram)
# se resuelve a través de sí mismo. Si alguno de esos nombres cayera en una
# lista por un falso positivo de un feed, el resolver se quedaría sin poder
# actualizar sus listas y sin poder avisar de nada, para siempre y en silencio.
#
# QUÉ SE CORRIGIÓ ACÁ, Y POR QUÉ IMPORTA
#
# La primera versión de esto matcheaba por SUFIJO e incluía `github.com` y
# `githubusercontent.com`. Eso convertía la excepción en un agujero: esos dos
# son hosting de contenido de cualquiera, y `raw.githubusercontent.com` es uno
# de los hosts más habituales en URLhaus para droppers y C2. Con matcheo por
# sufijo, `c2.raw.githubusercontent.com` quedaba exento del filtrado, no se
# registraba como bloqueo y no disparaba ninguna alerta. Y peor: si vos lo
# bloqueabas a mano, el panel te lo mostraba en la lista negra como si la regla
# estuviera activa. Un bloqueo que dice estar puesto y no lo está es peor que
# no tenerlo.
#
# Las tres reglas que lo acotan:
#
# 1. **Coincidencia exacta**, nunca por subdominio.
# 2. **La lista manual gana.** Si lo bloqueaste vos, se bloquea: es una
#    decisión explícita y el resolver no la puede pisar en silencio.
# 3. **Se registra.** La consulta queda en el historial con su motivo, así que
#    la excepción se ve en el panel en vez de ser invisible.
NOMBRES_PROPIOS = frozenset({
    "urlhaus.abuse.ch",
    "feodotracker.abuse.ch",
    "openphish.com",
    "raw.githubusercontent.com",   # StevenBlack/hosts
    "rdap.org",
    "api.telegram.org",
})


def es_dominio_propio(nombre: str) -> bool:
    """¿Este nombre exacto lo necesita el propio resolver para funcionar?"""
    return (nombre or "").strip().strip(".").lower() in NOMBRES_PROPIOS


# Techo del TTL que se le acepta a un upstream.
#
# Sin esto, una respuesta con `ttl = 4294967295` (el máximo del protocolo) se
# queda cacheada 136 años. Es la mitad de un envenenamiento de caché: alcanza
# con que una sola respuesta forjada entre una vez para que el nombre quede
# apuntando adonde quiera el atacante hasta que alguien reinicie el proceso.
# Un día es más que suficiente para cualquier cache de una casa.
MAX_TTL = 86400


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
        vista=None,
        block_mode: str = "nxdomain",
        geoip=None,
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
        # Preferencias de lo que se MUESTRA en el panel (filtro de ruido). No
        # participa de la decisión de bloquear: solo marca la fila del log.
        self.vista = vista
        # Con qué se le contesta a un dominio bloqueado. Ver `_respuesta_de_bloqueo`.
        self.block_mode = block_mode
        # Base local de país/ASN/proveedor. Puede no estar: en ese caso se
        # registra igual, solo que sin esos campos. Nunca sale a la red.
        self.geoip = geoip
        # cache_key -> (respuesta empaquetada sin el id, timestamp de vencimiento)
        #
        # Con su propio lock. Sin él, la limpieza del cache recorre el
        # diccionario mientras otros hilos lo escriben (hay un hilo por
        # consulta) y salta "dictionary changed size during iteration". Esa
        # excepción no la atrapa dnslib, así que la consulta se queda SIN
        # respuesta y el cliente espera hasta el timeout. Y aparece recién
        # cuando el cache se llena, o sea justo cuando hay tráfico.
        self._cache: dict[tuple[str, int], tuple[bytes, float]] = {}
        self._cache_lock = threading.Lock()
        # Conexiones TLS persistentes por IP de upstream: el handshake TLS
        # cuesta ~1 ida y vuelta extra, así que en vez de pagarlo en cada
        # consulta, se mantiene la conexión abierta y se reusa.
        #
        # Un lock POR UPSTREAM y no uno solo. Con uno solo, todas las consultas
        # del resolver se serializaban contra una única ida y vuelta a
        # internet: el techo quedaba en una consulta por RTT (unas 25 por
        # segundo con 40 ms), y una sola página web dispara treinta. Peor: si
        # el primario dejaba de responder, cada consulta esperaba su timeout de
        # 2 segundos EN FILA, así que la número diez esperaba veinte segundos.
        self._dot_conns: dict[str, ssl.SSLSocket] = {}
        self._dot_locks: dict[str, threading.Lock] = {}
        self._dot_registro = threading.Lock()
        # create_default_context() valida el certificado del upstream contra
        # las CAs del sistema y chequea que el nombre coincida (server_hostname):
        # exactamente lo que un cliente TLS bien hecho debe hacer.
        self._tls_context = ssl.create_default_context()

    # Con qué se le responde a un dominio bloqueado. No es una preferencia
    # estética: cambia cómo se comporta la aplicación que consultó.
    MODOS_DE_BLOQUEO = ("nxdomain", "zero", "localhost")

    # TTL corto a propósito para las respuestas de bloqueo. Si sacás un dominio
    # de la lista, no querés que el equipo siga con la respuesta vieja
    # cacheada media hora.
    TTL_BLOQUEO = 60

    def _respuesta_de_bloqueo(self, request: DNSRecord, qtype_id: int) -> DNSRecord:
        """Arma la respuesta para un dominio bloqueado, según el modo.

        Los tres modos y para qué sirve cada uno:

        - `nxdomain` (default): "ese nombre no existe". Es lo más limpio
          conceptualmente y lo que hace un resolver cuando de verdad no existe
          el nombre. El problema es que algunas aplicaciones lo interpretan
          como "la red está caída" y arrancan a reintentar, o muestran un
          cartel de sin conexión en vez de simplemente no cargar el anuncio.
        - `zero`: se responde 0.0.0.0 (y :: para IPv6). El nombre existe pero
          apunta a ninguna parte, así que la conexión falla al instante y sin
          reintentos de DNS. Es el modo que usa Pi-hole por defecto y suele
          romper menos cosas.
        - `localhost`: se responde 127.0.0.1 (y ::1). Igual que el anterior,
          pero el intento de conexión se queda en la propia máquina. Sirve si
          tenés algo escuchando ahí que quiera mostrar una página de "esto
          está bloqueado".

        Para los tipos que no son A ni AAAA (TXT, MX, SRV...) siempre se
        responde NXDOMAIN, en cualquier modo: no se puede fabricar un TXT
        "vacío" que signifique bloqueado, y devolver una respuesta inventada
        sería peor que decir que no existe.
        """
        reply = request.reply()
        modo = self.block_mode if self.block_mode in self.MODOS_DE_BLOQUEO else "nxdomain"

        if modo == "nxdomain":
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        ipv4, ipv6 = ("127.0.0.1", "::1") if modo == "localhost" else ("0.0.0.0", "::")
        if qtype_id == QTYPE.A:
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ipv4), ttl=self.TTL_BLOQUEO))
        elif qtype_id == QTYPE.AAAA:
            reply.add_answer(
                RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(ipv6), ttl=self.TTL_BLOQUEO)
            )
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply

    def _es_ruido(self, qname: str) -> bool:
        """¿Este nombre es ruido de fondo (telemetría, comprobación de
        conectividad, actualizaciones)? Solo afecta lo que se MUESTRA."""
        vista = self.vista
        if vista is None:
            return False
        try:
            return bool(vista.es_ruidoso(qname))
        except Exception:  # noqa: BLE001 - el panel no puede tumbar el resolver
            return False

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        start = time.time()
        # Se normaliza una sola vez y se usa la MISMA cadena para filtrar,
        # cachear y loguear. Que el punto final del FQDN o un nombre
        # internacional den una cadena distinta según dónde se lo mire es
        # justo el agujero que hace que una regla no matchee: se filtra un
        # nombre y se resuelve otro.
        qname = normalizar_nombre_consultado(str(request.q.qname))
        qtype_id = request.q.qtype
        qtype_name = QTYPE.get(qtype_id, str(qtype_id))
        client_ip = handler.client_address[0] if hasattr(handler, "client_address") else "-"
        ruido = self._es_ruido(qname)

        decision, categoria = self._decidir(qname)

        if decision == "bloquear":
            reply = self._respuesta_de_bloqueo(request, qtype_id)
            self.logger_db.log_query(
                client_ip, qname, qtype_name, True,
                reason=f"dominio en blocklist: {qname}", source="blocklist",
                duration_ms=(time.time() - start) * 1000, noisy=ruido,
                category=categoria,
            )
            return reply

        # La excepción de los nombres propios se registra en vez de pasar
        # invisible: tiene que verse en el panel que se dejó pasar y por qué.
        motivo = (
            "permitido: el resolver necesita este nombre para funcionar"
            if decision == "propio" else ""
        )

        cache_key = (qname, qtype_id)
        cached = self._leer_cache(cache_key)
        if cached is not None:
            reply = self._parsear(cached)
            if reply is not None:
                reply.header.id = request.header.id
                self.logger_db.log_query(
                    client_ip, qname, qtype_name, False, source="cache",
                    reason=motivo, duration_ms=(time.time() - start) * 1000,
                    noisy=ruido, **self._datos_de(reply),
                )
                return reply

        response_bytes, source = self._forward_to_upstream(request)
        duration_ms = (time.time() - start) * 1000

        reply = self._parsear(response_bytes) if response_bytes else None
        if reply is None:
            # Sin respuesta usable: puede ser que ningún upstream contestara, o
            # que lo que contestó no se pudiera parsear (una respuesta cortada
            # por el tope de 4 KB de UDP, por ejemplo). Antes esto se iba como
            # excepción y el cliente se quedaba esperando el timeout SIN que
            # quedara una sola fila en el historial: el peor tipo de falla,
            # porque no se puede ni diagnosticar.
            respuesta = request.reply()
            respuesta.header.rcode = RCODE.SERVFAIL
            self.logger_db.log_query(
                client_ip, qname, qtype_name, False,
                reason="ningún servidor upstream respondió una respuesta usable",
                source="error", duration_ms=duration_ms, noisy=ruido,
            )
            return respuesta

        ttl = max((rr.ttl for rr in reply.rr), default=self.min_cache_ttl)
        # Los dos topes importan. El de abajo es una preferencia (no consultar
        # de nuevo cada 5 segundos); el de arriba es defensa: sin él, una sola
        # respuesta con el TTL máximo del protocolo se queda 136 años en el
        # cache.
        ttl = min(MAX_TTL, max(ttl, self.min_cache_ttl))
        self._guardar_en_cache(cache_key, response_bytes, ttl)

        self.logger_db.log_query(
            client_ip, qname, qtype_name, False, source=source, reason=motivo,
            duration_ms=duration_ms, noisy=ruido, **self._datos_de(reply),
        )
        return reply

    def _decidir(self, qname: str) -> tuple[str, str]:
        """Qué hacer con este nombre: "bloquear", "propio" o "resolver".

        El orden es el punto de esta función, y por eso está separada del resto:

        1. **La lista blanca gana sobre todo.** Es la regla más vieja del
           proyecto y está en el README: si lo permitiste explícitamente, se
           permite.
        2. **La lista negra MANUAL**, que gana sobre la excepción de los
           nombres propios. Si lo bloqueaste vos, es una decisión explícita y
           el resolver no la puede pisar en silencio: un bloqueo que el panel
           muestra como puesto y no se aplica es peor que no tenerlo.
        3. Los nombres que el propio resolver necesita para funcionar.
        4. La lista negra completa (manual + feeds).
        """
        if self.allowlist is not None and self.allowlist.is_allowed(qname):
            return "resolver", ""
        if qname in self.blocklist.manual_entries():
            return "bloquear", self.blocklist.categoria_de(qname)
        if es_dominio_propio(qname):
            return "propio", ""
        if self.blocklist.is_blocked(qname):
            return "bloquear", self.blocklist.categoria_de(qname)
        return "resolver", ""

    @staticmethod
    def _parsear(datos: bytes | None) -> DNSRecord | None:
        """Parsea una respuesta DNS sin dejar que una malformada tumbe nada.

        dnslib levanta excepciones de varios tipos con datos cortados o
        inválidos, y el manejador de dnslib solo atrapa DNSError: cualquier
        otra sube y el cliente se queda sin respuesta.
        """
        if not datos:
            return None
        try:
            return DNSRecord.parse(datos)
        except Exception:  # noqa: BLE001 - dnslib tira varias cosas distintas
            return None

    def _primera_direccion(self, reply: DNSRecord) -> str:
        """La primera IP de la respuesta, si la hay.

        Es adónde va a terminar conectándose el equipo que preguntó. El
        resolver ya la tiene en la mano, así que geolocalizarla no cuesta una
        consulta extra: es leer lo que ya vino.
        """
        for rr in reply.rr:
            if rr.rtype in (QTYPE.A, QTYPE.AAAA):
                return str(rr.rdata)
        return ""

    def _datos_de(self, reply: DNSRecord) -> dict:
        """Lo que se puede saber mirando la respuesta: DNSSEC, IP y geografía.

        El flag AD ("Authenticated Data") significa que **el upstream** validó
        la firma DNSSEC de esa respuesta. NO significa que la hayamos validado
        nosotros: validar de verdad es implementar la cadena de confianza
        entera, y este proyecto no escribe criptografía propia. El panel lo
        dice con todas las letras, porque decir "dominio firmado" a secas sería
        atribuirse un trabajo que hizo Quad9.
        """
        datos = {"dnssec": 1 if reply.header.ad else 0}
        ip = self._primera_direccion(reply)
        if not ip:
            return datos
        datos["dest_ip"] = ip
        if self.geoip is not None and self.geoip.disponible:
            geo = self.geoip.buscar(ip)
            datos["country"] = geo.get("pais", "")
            datos["asn"] = geo.get("asn", "")
            datos["provider"] = geo.get("proveedor", "")
        return datos

    # Techo de entradas del cache. Sin techo, el cache es un agujero de
    # memoria con forma de feature: cualquier cosa que consulte nombres
    # distintos sin parar -malware con dominios generados por algoritmo,
    # tunneling por DNS, o un simple escaneo- lo llena hasta que el proceso
    # se queda sin RAM. Y como cada entrada es una respuesta DNS entera, no
    # hace falta demasiado. 20.000 entradas son unos pocos MB y cubren de
    # sobra la navegación real de una casa.
    MAX_CACHE = 20_000

    # Techo del tamaño de una respuesta guardada. Por TLS se pueden recibir
    # hasta 64 KB por respuesta, así que 20.000 entradas de ese tamaño serían
    # más de un giga de RAM. Una respuesta normal no pasa de unos cientos de
    # bytes: lo que no entra acá se responde igual, solo que no se cachea.
    MAX_TAMANIO_RESPUESTA = 4096

    def _leer_cache(self, cache_key) -> bytes | None:
        with self._cache_lock:
            guardado = self._cache.get(cache_key)
            if guardado is None or time.time() >= guardado[1]:
                return None
            return guardado[0]

    def _guardar_en_cache(self, cache_key, response_bytes: bytes, ttl: float) -> None:
        if len(response_bytes) > self.MAX_TAMANIO_RESPUESTA:
            return
        with self._cache_lock:
            if len(self._cache) >= self.MAX_CACHE:
                ahora = time.time()
                # Primero lo vencido, que no le sirve a nadie.
                vencidas = [k for k, (_, vence) in self._cache.items() if vence <= ahora]
                for clave in vencidas:
                    self._cache.pop(clave, None)
                # Si aun así está lleno, se tira la porción más vieja. Los dict
                # de Python conservan el orden de inserción, así que las
                # primeras claves son las que hace más tiempo que no se
                # renuevan.
                if len(self._cache) >= self.MAX_CACHE:
                    for clave in list(self._cache)[: max(1, self.MAX_CACHE // 10)]:
                        self._cache.pop(clave, None)
            self._cache[cache_key] = (response_bytes, time.time() + ttl)

    def clear_cache(self) -> None:
        """Vacía el cache de respuestas en memoria. Pensado para el botón
        "Borrar cache" del dashboard/menú .bat: la próxima consulta de
        cualquier dominio se vuelve a pedir a upstream en vez de servirse
        desde una respuesta guardada."""
        with self._cache_lock:
            self._cache.clear()

    def cache_size(self) -> int:
        with self._cache_lock:
            return len(self._cache)

    def _forward_to_upstream(self, request: DNSRecord) -> tuple[bytes | None, str]:
        """Orquesta el reenvío según el modo configurado: primero DoT (si
        corresponde), y si ningún upstream respondió por TLS, cae a UDP en
        texto plano - solo si `dot_fallback_to_udp` lo permite. La idea:
        mejor una consulta en texto plano que quedarse sin internet en una
        red que bloquea el puerto 853 (cafés, universidades, etc.)."""
        request = self._pedido_para_upstream(request)
        if self.upstream_mode == "dot":
            data, label = self._forward_via_dot(request)
            if data is not None:
                return data, label
            if not self.dot_fallback_to_udp:
                return None, "error"
        return self._forward_via_udp(request)

    @staticmethod
    def _pedido_para_upstream(request: DNSRecord) -> DNSRecord:
        """Copia del pedido con el bit AD prendido, para preguntar por DNSSEC.

        Sin esto la estadística de DNSSEC sería una mentira. Un resolver que
        valida (Quad9, Cloudflare) solo marca la respuesta como autenticada si
        el que preguntó dijo que le interesa, así que reenviando el pedido tal
        como vino del cliente el flag AD llegaría casi siempre en cero y el
        panel mostraría "0% firmado" para toda internet.

        Se trabaja sobre una copia y no sobre el pedido original porque ese
        mismo objeto se usa después para armar la respuesta al cliente.
        """
        copia = DNSRecord.parse(request.pack())
        copia.header.ad = 1
        return copia

    def _forward_via_udp(self, request: DNSRecord) -> tuple[bytes | None, str]:
        """Modo clásico: intenta el servidor primario y, si falla, el de
        respaldo. Texto plano por UDP al puerto 53.

        Las tres validaciones de abajo no son opcionales: UDP no tiene sesión,
        así que sin ellas **cualquiera puede contestar** por el upstream y esa
        respuesta forjada queda cacheada bajo la clave de la consulta legítima.
        Es envenenamiento de caché clásico, y lo comprobé: sin esto, un
        datagrama con un ID cualquiera y una pregunta distinta se aceptaba, se
        guardaba en el cache y se le servía a todos los que preguntaran después.

        1. `connect()` en vez de `sendto`: le pide al kernel que descarte los
           datagramas que no vengan de la IP y el puerto del upstream. Es la
           barrera más barata y la que más entropía agrega.
        2. El ID del mensaje tiene que coincidir con el que mandamos.
        3. La pregunta de la respuesta tiene que ser la que hicimos.

        Con las tres, forjar una respuesta pasa de "meter un paquete" a acertar
        el puerto efímero y los 16 bits del ID desde la IP correcta.
        """
        payload = request.pack()
        for upstream, label in (
            (self.upstream_primary, "upstream_primary"),
            (self.upstream_fallback, "upstream_fallback"),
        ):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(self.upstream_timeout)
                sock.connect((upstream, 53))
                sock.send(payload)
                # Se lee en un bucle: si llega basura de un tercero que igual
                # pasó el filtro del kernel, se descarta y se sigue esperando
                # la buena hasta que venza el timeout.
                fin = time.time() + self.upstream_timeout
                while time.time() < fin:
                    sock.settimeout(max(0.05, fin - time.time()))
                    data = sock.recv(4096)
                    if self._respuesta_valida(data, request):
                        return data, label
            except OSError:
                continue
            finally:
                sock.close()
        return None, "error"

    @staticmethod
    def _respuesta_valida(data: bytes, request: DNSRecord) -> bool:
        """¿Esta respuesta es realmente la de nuestra consulta?"""
        try:
            respuesta = DNSRecord.parse(data)
        except Exception:  # noqa: BLE001 - dnslib tira varias cosas distintas
            return False
        if respuesta.header.id != request.header.id:
            return False
        if not respuesta.questions or not request.questions:
            return False
        nuestra = request.q
        suya = respuesta.q
        return (
            str(suya.qname).lower() == str(nuestra.qname).lower()
            and suya.qtype == nuestra.qtype
            and suya.qclass == nuestra.qclass
        )

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
        with self._lock_de(upstream_ip):
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

    def _lock_de(self, upstream_ip: str) -> threading.Lock:
        """El lock de ESE upstream, creándolo si es la primera vez.

        Uno por upstream y no uno global: ver el comentario de `_dot_locks`.
        El `_dot_registro` protege solo la creación, que dura nanosegundos, y
        no la consulta, que dura una ida y vuelta a internet.
        """
        with self._dot_registro:
            lock = self._dot_locks.get(upstream_ip)
            if lock is None:
                lock = threading.Lock()
                self._dot_locks[upstream_ip] = lock
            return lock

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

    def cerrar_conexiones_tls(self) -> None:
        """Suelta todas las conexiones TLS persistentes.

        Lo llama el panel al cambiar el modo de upstream: si no, se seguirían
        usando las conexiones viejas. Va acá y no en el panel para que el
        cierre pase por el lock de cada upstream: antes el panel recorría el
        diccionario y cerraba los sockets por su cuenta, desde otro hilo,
        mientras una consulta podía estar escribiendo en ese mismo socket.
        """
        with self._dot_registro:
            upstreams = list(self._dot_conns)
        for ip in upstreams:
            with self._lock_de(ip):
                self._dot_close(ip)


class ServidorDNS:
    """El resolver escuchando por UDP **y por TCP**, como una sola cosa.

    Lo de TCP no es opcional aunque casi todo el tráfico sea UDP: cuando una
    respuesta no entra en un datagrama, el servidor la manda truncada con el
    flag TC y el cliente tiene que reintentar por TCP en el mismo puerto. Sin
    nadie escuchando ahí, esas consultas no se resuelven nunca. Lo pide el
    RFC 7766 y se nota con respuestas TXT o cadenas largas de CNAME, que es
    justo lo que consulta un cliente de correo o cualquier cosa con SPF.

    Los dos se envuelven en una clase para que quien los use no tenga que
    acordarse de arrancar, parar y chequear dos servidores.
    """

    def __init__(self, host: str, port: int, resolver: ThreatIntelResolver):
        self.udp = DNSServer(resolver, address=host, port=port,
                             logger=_QUIET_LOGGER, tcp=False)
        # Con `port=0` el UDP toma un puerto efímero y el TCP tiene que tomar
        # EL MISMO, o el cliente que reintenta por TCP no encuentra a nadie.
        # Solo pasa en los tests, pero un servidor que en pruebas escucha en
        # dos puertos distintos no está probando lo que corre en producción.
        real = port or self.udp.server.server_address[1]
        self.tcp = DNSServer(resolver, address=host, port=real,
                             logger=_QUIET_LOGGER, tcp=True)

    @property
    def server(self):
        """El servidor UDP, para quien necesite su dirección."""
        return self.udp.server

    def start_thread(self) -> None:
        self.udp.start_thread()
        self.tcp.start_thread()

    def isAlive(self) -> bool:  # noqa: N802 - así lo llama dnslib
        return self.udp.isAlive()

    def stop(self) -> None:
        for servidor in (self.udp, self.tcp):
            try:
                servidor.stop()
            except Exception:  # noqa: BLE001 - parar no puede fallar el apagado
                pass


def build_dns_server(host: str, port: int, resolver: ThreatIntelResolver) -> ServidorDNS:
    return ServidorDNS(host, port, resolver)
