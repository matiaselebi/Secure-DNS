"""País, ASN y proveedor de una IP, con una base LOCAL y sin dependencias.

La regla que manda acá: **nunca una consulta a una API por conexión**. El
proxy ve todas las conexiones de la PC; a diez por segundo, una llamada de
red por cada una destruiría el rendimiento y quemaría cualquier cupo. Así que
la resolución se hace contra una base descargada, y la descarga pasa una vez
por mes.

Por qué SQLite y no una librería de `.mmdb`: leer el formato de MaxMind a
mano no es razonable, y usar su lector significa una dependencia nueva. Pero
las bases gratuitas también se publican en CSV, y un CSV de rangos entra
perfecto en SQLite: se convierte cada rango a un par de enteros, se indexa
por el inicio, y cada consulta es una búsqueda por índice. Eso sale con la
librería estándar y encima queda inspeccionable con cualquier visor de
SQLite.

Si la base no está descargada, todo esto devuelve vacío y el resolver funciona
igual: el país y el ASN son información extra del registro, no parte de la
decisión de bloquear.
"""

import ipaddress
import sqlite3
import threading
from contextlib import closing
from pathlib import Path


def ip_a_entero(ip: str) -> int | None:
    """IPv4 a entero. None si no es una IPv4 válida."""
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if direccion.version != 4:
        return None
    return int(direccion)


class GeoIP:
    """Consulta el país y el ASN de una IP contra la base local."""

    # Cuántas resoluciones se recuerdan en memoria. Un navegador vuelve una y
    # otra vez a las mismas IPs, así que con pocas entradas ya casi no se
    # toca el disco.
    MAX_CACHE = 4096

    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._cache: dict[str, dict] = {}
        self._existe = Path(self.db_path).exists()
        if self._existe:
            self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_schema(self) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rangos (
                    inicio INTEGER NOT NULL,
                    fin INTEGER NOT NULL,
                    pais TEXT,
                    asn TEXT,
                    proveedor TEXT
                )
                """
            )
            # El índice por `inicio` es lo que hace que cada consulta sea una
            # búsqueda y no un recorrido: sin esto, con medio millón de
            # rangos, cada conexión costaría una eternidad.
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rangos_inicio ON rangos (inicio)")
            conn.commit()

    @property
    def disponible(self) -> bool:
        """¿Hay base descargada? Si no, el resolver anda igual, sin estos datos."""
        return self._existe

    def buscar(self, ip: str) -> dict:
        """Devuelve {"pais", "asn", "proveedor"} para esa IP. Vacío si no hay
        base, si la IP no es v4, o si el rango no está cubierto."""
        vacio = {"pais": "", "asn": "", "proveedor": ""}
        if not ip or not self._existe:
            return vacio

        cacheado = self._cache.get(ip)
        if cacheado is not None:
            return cacheado

        valor = ip_a_entero(ip)
        if valor is None:
            return vacio

        try:
            with self._lock, closing(self._connect()) as conn, conn:
                fila = conn.execute(
                    # El rango candidato es el último que empieza antes o en
                    # la IP; después se confirma que también la contenga.
                    "SELECT fin, pais, asn, proveedor FROM rangos "
                    "WHERE inicio <= ? ORDER BY inicio DESC LIMIT 1",
                    (valor,),
                ).fetchone()
        except sqlite3.Error:
            return vacio

        if fila is None or valor > fila[0]:
            resultado = vacio
        else:
            resultado = {
                "pais": fila[1] or "",
                "asn": fila[2] or "",
                "proveedor": fila[3] or "",
            }

        if len(self._cache) >= self.MAX_CACHE:
            self._cache.clear()
        self._cache[ip] = resultado
        return resultado

    def cantidad_de_rangos(self) -> int:
        if not self._existe:
            return 0
        try:
            with self._lock, closing(self._connect()) as conn, conn:
                return conn.execute("SELECT COUNT(*) FROM rangos").fetchone()[0]
        except sqlite3.Error:
            return 0
