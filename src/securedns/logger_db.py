"""Logging estructurado de cada consulta DNS, en SQLite.

Mismas decisiones que el logger de SecureProxy, por las mismas razones: un
resolver que atiende a toda la casa ve MUCHAS más consultas que las que un
humano genera a mano (cada página web dispara decenas), así que la base
crece rápido y para siempre si nadie la recorta. Y el panel consulta esta
tabla en cada refresco, así que todo lo que se muestra tiene que salir de
una query indexada y no de traer filas a Python para filtrarlas ahí.
"""

import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .deteccion import (
    MINIMO_DE_CONSULTAS,
    TIPOS_DE_DATOS,
    dominio_padre,
    entropia,
    evaluar_actividad,
    evaluar_grupo,
    parte_variable,
)


class LoggerDB:
    # Cada cuántas inserciones se chequea si hay que recortar. No va en cada
    # INSERT porque sería un COUNT por consulta DNS.
    PRUNE_EVERY = 500

    def __init__(self, db_path: str, max_rows: int = 200_000):
        self.db_path = db_path
        self.max_rows = max_rows
        self._inserts_since_prune = 0
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_schema(self) -> None:
        # `closing` además del context manager de la conexión: el `with conn`
        # de sqlite3 hace commit/rollback pero NO cierra el descriptor. Sin
        # esto, cada refresco del panel dejaba un fd abierto hasta que el
        # recolector pasara, y el proceso terminaba quedándose sin.
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT,
                    domain TEXT,
                    qtype TEXT,
                    blocked INTEGER NOT NULL,
                    reason TEXT,
                    source TEXT,
                    duration_ms REAL
                )
                """
            )

            # Marca de "esto es ruido de fondo": telemetría, comprobaciones de
            # conectividad, actualizaciones. No cambia NADA de lo que se
            # bloquea; solo permite sacarlo de la vista sin recorrer la lista
            # de dominios ruidosos fila por fila en cada refresco.
            columnas = {fila[1] for fila in conn.execute("PRAGMA table_info(queries)")}
            if "noisy" not in columnas:
                conn.execute("ALTER TABLE queries ADD COLUMN noisy INTEGER NOT NULL DEFAULT 0")
            # De qué es el bloqueo: malware, phishing, publicidad, manual. Sale
            # del feed donde apareció el dominio (ver blocklist.py), no de una
            # clasificación inventada acá. Vacío en las consultas que no se
            # bloquearon.
            if "category" not in columnas:
                conn.execute("ALTER TABLE queries ADD COLUMN category TEXT DEFAULT ''")
            # Dominio padre de la consulta ("a3f9.tunel.malo.com" -> "malo.com").
            # Se guarda calculado en vez de derivarlo en cada consulta porque la
            # detección de tunneling agrupa por acá, y agrupar por una expresión
            # que SQLite no puede indexar convierte cada refresco del panel en un
            # scan completo de la tabla.
            if "parent" not in columnas:
                conn.execute("ALTER TABLE queries ADD COLUMN parent TEXT DEFAULT ''")
            # Lo que se puede leer de la respuesta sin salir a ningún lado:
            # si el upstream la validó con DNSSEC, a qué IP resolvió, y de qué
            # país/ASN/proveedor es esa IP según la base local.
            for nueva, tipo in (
                ("dnssec", "INTEGER DEFAULT 0"),
                ("dest_ip", "TEXT DEFAULT ''"),
                ("country", "TEXT DEFAULT ''"),
                ("asn", "TEXT DEFAULT ''"),
                ("provider", "TEXT DEFAULT ''"),
            ):
                if nueva not in columnas:
                    conn.execute(f"ALTER TABLE queries ADD COLUMN {nueva} {tipo}")

            # Los índices son lo que hace que el panel abra rápido con cientos
            # de miles de filas: sin ellos cada refresco es un scan completo.
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_queries_blocked ON queries (blocked, id DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_queries_timestamp ON queries (timestamp)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queries_noisy ON queries (noisy)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries (domain)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_queries_parent ON queries (parent, client_ip)"
            )

            # Resúmenes por día, para poder mostrar meses de historia sin
            # guardar meses de consultas.
            #
            # El historial se recorta a `max_rows`, así que con una casa activa
            # no llega ni a una semana. Mostrar "últimos 12 meses" leyendo de
            # `queries` sería mentir: diría cero para todo lo que ya se podó.
            # Acá se guarda el agregado de cada día cerrado, que ocupa una fila
            # por día y sobrevive al recorte.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS resumen_diario (
                    fecha TEXT PRIMARY KEY,
                    total INTEGER NOT NULL,
                    bloqueadas INTEGER NOT NULL,
                    cacheadas INTEGER NOT NULL
                )
                """
            )
            # Hasta qué id de `queries` ya está sumado en `resumen_diario`.
            #
            # Es lo que hace correcto al histórico. La primera versión
            # consolidaba "los días cerrados", y eso perdía datos: el recorte
            # borra por id sin mirar el día, así que las filas del día EN CURSO
            # se iban antes de que ese día se consolidara. Con una casa activa
            # el resumen guardaba una fracción de lo que realmente pasó, o sea
            # que el histórico quedaba mal justo en las redes donde importa.
            #
            # Con el marcador, la regla es simple y no se puede violar: se
            # consolida todo lo nuevo (incluido lo de hoy), y el recorte solo
            # puede borrar lo que ya está consolidado.
            conn.execute(
                "CREATE TABLE IF NOT EXISTS consolidacion "
                "(clave TEXT PRIMARY KEY, valor INTEGER NOT NULL)"
            )
            conn.commit()

    # ---------- escritura ----------

    def log_query(
        self,
        client_ip: str,
        domain: str,
        qtype: str,
        blocked: bool,
        reason: str = "",
        source: str = "",
        duration_ms: float = 0.0,
        noisy: bool = False,
        category: str = "",
        dnssec: int = 0,
        dest_ip: str = "",
        country: str = "",
        asn: str = "",
        provider: str = "",
    ) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        padre = dominio_padre(domain)
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO queries
                    (timestamp, client_ip, domain, qtype, blocked, reason,
                     source, duration_ms, noisy, category, parent,
                     dnssec, dest_ip, country, asn, provider)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, client_ip, domain, qtype, int(blocked), reason,
                 source, duration_ms, int(noisy), category or "", padre,
                 int(dnssec), dest_ip or "", country or "", asn or "", provider or ""),
            )
            conn.commit()
            # Adentro del lock: era el único acceso a la base que no lo tomaba,
            # así que con varias consultas en paralelo se perdían incrementos y
            # el recorte se atrasaba de forma impredecible.
            self._inserts_since_prune += 1
        self._maybe_prune()

    def recalcular_padres(self) -> int:
        """Completa la columna `parent` de las filas que no la tengan.

        Se corre al arrancar. Existe por lo mismo que `remarcar_ruido`: una
        base que ya venía usándose no tiene el dato, y sin esto la detección de
        tunneling arrancaría ciega sobre todo el historial viejo hasta que pase
        tráfico nuevo.

        Es barato aunque la tabla sea grande: la cantidad de dominios DISTINTOS
        es de unos miles como mucho, así que el cálculo se hace en Python sobre
        esa lista y el UPDATE va por igualdad de dominio, apoyado en su índice.
        """
        with self._lock, closing(self._connect()) as conn, conn:
            faltantes = [
                d for (d,) in conn.execute(
                    "SELECT DISTINCT domain FROM queries "
                    "WHERE parent IS NULL OR parent = ''"
                ) if d
            ]
            if not faltantes:
                return 0
            cambios = 0
            for dominio in faltantes:
                cur = conn.execute(
                    "UPDATE queries SET parent = ? WHERE domain = ? "
                    "AND (parent IS NULL OR parent = '')",
                    (dominio_padre(dominio), dominio),
                )
                cambios += cur.rowcount
            conn.commit()
            return cambios

    # ---------- retención ----------

    def _maybe_prune(self) -> None:
        if self.max_rows <= 0:
            return
        if self._inserts_since_prune < self.PRUNE_EVERY:
            return
        self._inserts_since_prune = 0
        self.prune()

    def prune(self) -> int:
        """Borra las consultas más viejas que exceden `max_rows`. Devuelve
        cuántas borró.

        Se borra por id (autoincremental): las de id más chico son las más
        viejas, sin depender de parsear fechas.
        """
        if self.max_rows <= 0:
            return 0
        # Antes de borrar nada, guardar el resumen de los días cerrados. Sin
        # esto el recorte se llevaría puesta la única copia de esos números y
        # el histórico de meses mostraría ceros para siempre.
        #
        # Va acá afuera y no adentro del `with` porque el lock no es
        # reentrante: llamarlo con el lock tomado colgaría el proceso.
        self.consolidar_dias()
        with self._lock, closing(self._connect()) as conn, conn:
            total = conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
            sobrante = total - self.max_rows
            if sobrante <= 0:
                return 0
            marca = conn.execute(
                "SELECT valor FROM consolidacion WHERE clave = 'ultimo_id'"
            ).fetchone()
            hasta = marca[0] if marca else 0
            # Solo se borra lo que ya está sumado al resumen diario. Sin este
            # límite el recorte se llevaba filas que todavía no habían entrado
            # al histórico, y esos números no se recuperaban nunca.
            conn.execute(
                "DELETE FROM queries WHERE id IN ("
                "  SELECT id FROM queries WHERE id <= ? ORDER BY id ASC LIMIT ?"
                ")",
                (hasta, sobrante),
            )
            conn.commit()
            return sobrante

    def compact(self) -> None:
        """Devuelve al disco el espacio de las filas borradas (VACUUM).

        Sin esto SQLite marca las páginas como libres para reusarlas, pero el
        archivo sigue ocupando los mismos megabytes.
        """
        # VACUUM no corre dentro de una transacción, así que la conexión se
        # abre a mano en vez de usar el context manager.
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("VACUUM")
            finally:
                conn.close()

    def clear(self) -> int:
        """Vacía el historial entero y compacta. Devuelve cuántas borró."""
        with self._lock, closing(self._connect()) as conn, conn:
            borradas = conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
            conn.execute("DELETE FROM queries")
            conn.commit()
        self.compact()
        return borradas

    # ---------- filtro de ruido (de VISTA, no de filtrado) ----------

    @staticmethod
    def _filtro_ocultos(ocultar: bool) -> tuple[str, list]:
        """Fragmento SQL que deja afuera las consultas marcadas como ruido.

        Se apoya en la columna `noisy`, escrita al insertar y recalculada por
        `remarcar_ruido` cuando cambia la lista. La alternativa -comparar el
        dominio contra los ~50 de la lista en cada query- es la que se probó
        en SecureProxy y no sirve: el panel pasaba de milisegundos a segundos.

        Tiene que hacerse en SQL y no filtrando después en Python porque las
        agregaciones usan GROUP BY con LIMIT: filtrando después, los dominios
        ruidosos igual se comen los primeros puestos del Top 10 y queda una
        lista de tres elementos.
        """
        if not ocultar:
            return "", []
        return "noisy = 0", []

    def remarcar_ruido(self, es_ruidoso) -> int:
        """Recalcula la marca de ruido de TODO el historial. Devuelve cuántas
        filas cambiaron.

        Se corre al arrancar, para que una base que ya existía (o una lista
        editada a mano) quede consistente desde el primer refresco. Es barato
        aunque la tabla sea grande: la cantidad de dominios DISTINTOS es de
        unos cientos, así que el matcheo se hace en Python sobre esa lista
        chica y el UPDATE va por igualdad, apoyado en su índice.
        """
        with self._lock, closing(self._connect()) as conn, conn:
            dominios = [d for (d,) in conn.execute("SELECT DISTINCT domain FROM queries")]
            ruidosos = [d for d in dominios if d and es_ruidoso(d)]
            cambios = 0
            if ruidosos:
                # De a tandas: SQLite tiene un techo de parámetros por consulta
                # (999 en compilaciones viejas), y una base grande puede tener
                # más dominios ruidosos distintos que eso.
                TANDA = 500
                for i in range(0, len(ruidosos), TANDA):
                    tanda = ruidosos[i:i + TANDA]
                    marcas = ",".join("?" * len(tanda))
                    cur = conn.execute(
                        f"UPDATE queries SET noisy = 1 WHERE noisy = 0 "
                        f"AND domain IN ({marcas})",
                        tanda,
                    )
                    cambios += cur.rowcount
                marcas = ",".join("?" * len(ruidosos[:TANDA]))
                # El desmarcado necesita la lista COMPLETA en un solo NOT IN,
                # así que se hace con una tabla temporal en vez de por tandas.
                conn.execute("CREATE TEMP TABLE IF NOT EXISTS ruidosos (d TEXT PRIMARY KEY)")
                conn.execute("DELETE FROM ruidosos")
                conn.executemany("INSERT OR IGNORE INTO ruidosos VALUES (?)",
                                 [(d,) for d in ruidosos])
                cur = conn.execute(
                    "UPDATE queries SET noisy = 0 WHERE noisy = 1 "
                    "AND domain NOT IN (SELECT d FROM ruidosos)"
                )
                cambios += cur.rowcount
            else:
                cur = conn.execute("UPDATE queries SET noisy = 0 WHERE noisy = 1")
                cambios += cur.rowcount
            conn.commit()
            return cambios

    # ---------- lectura ----------

    COLUMNAS = (
        "id", "timestamp", "client_ip", "domain", "qtype",
        "blocked", "reason", "source", "duration_ms", "noisy", "category", "parent",
        "dnssec", "dest_ip", "country", "asn", "provider",
    )

    def _filas(self, cur) -> list[dict]:
        return [dict(zip(self.COLUMNAS, fila)) for fila in cur.fetchall()]

    def recent_blocked(self, limit: int = 25) -> list[tuple]:
        """(timestamp, dominio, motivo) de los últimos bloqueos. Se mantiene
        con esta forma exacta porque la usa el menú .bat."""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "SELECT timestamp, domain, reason FROM queries "
                "WHERE blocked = 1 ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            return cur.fetchall()

    def buscar(
        self,
        texto: str = "",
        solo_bloqueadas: bool = True,
        limit: int = 50,
        ocultar: bool = False,
        qtype: str = "",
        categoria: str = "",
        cliente: str = "",
    ) -> list[dict]:
        """Historial filtrado, con todas las columnas de cada consulta.

        `texto` busca por dominio, IP del cliente o motivo, con coincidencia
        parcial: escribir "google" trae también "www.google.com". Cuando hay
        búsqueda, el filtro de "solo bloqueadas" se ignora a propósito: si
        estás auditando qué hizo un equipo de la casa querés ver todo, no
        solo lo que se le bloqueó. Y por la misma razón se ignora el filtro
        de ruido: si buscás un dominio de telemetría, es porque lo querés
        ver.
        """
        condiciones: list[str] = []
        parametros: list = []
        texto = (texto or "").strip()
        if texto:
            condiciones.append("(domain LIKE ? OR client_ip LIKE ? OR reason LIKE ?)")
            parametros += [f"%{texto}%"] * 3
        else:
            filtro, params_ocultos = self._filtro_ocultos(ocultar)
            if filtro:
                condiciones.append(filtro)
                parametros += params_ocultos
            if solo_bloqueadas:
                condiciones.append("blocked = 1")

        # Los filtros de abajo se aplican SIEMPRE, con o sin texto: son
        # precisos por definición, así que no hay motivo para ignorarlos como
        # se ignora el "solo bloqueadas" cuando hay búsqueda.
        if qtype:
            condiciones.append("qtype = ?")
            parametros.append(qtype.upper())
        if categoria:
            condiciones.append("category = ?")
            parametros.append(categoria.lower())
        if cliente:
            condiciones.append("client_ip = ?")
            parametros.append(cliente)

        where = f"WHERE {' AND '.join(condiciones)}" if condiciones else ""

        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                f"SELECT {', '.join(self.COLUMNAS)} FROM queries {where} "
                "ORDER BY id DESC LIMIT ?",
                (*parametros, limit),
            )
            return self._filas(cur)

    def stats(self, ocultar: bool = False) -> dict:
        """Totales de las tarjetas. `hidden_queries` dice cuántas consultas
        quedaron fuera de la cuenta por el filtro de ruido: mostrarlo es lo
        que hace que el filtro sea honesto en vez de una mentira piadosa."""
        filtro, params = self._filtro_ocultos(ocultar)
        where = f"WHERE {filtro}" if filtro else ""
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            total = conn.execute(f"SELECT COUNT(*) FROM queries {where}", params).fetchone()[0]
            blocked = conn.execute(
                f"SELECT COUNT(*) FROM queries WHERE blocked = 1{y_ademas}", params
            ).fetchone()[0]
            cached = conn.execute(
                f"SELECT COUNT(*) FROM queries WHERE source = 'cache'{y_ademas}", params
            ).fetchone()[0]
            ocultas = conn.execute("SELECT COUNT(*) FROM queries WHERE noisy = 1").fetchone()[0]
        return {
            "total_queries": total,
            "blocked_queries": blocked,
            "cached_queries": cached,
            "hidden_queries": ocultas if ocultar else 0,
        }

    def por_hora(self, horas: int = 24, ocultar: bool = False) -> list[tuple[str, int, int]]:
        """(hora, total, bloqueadas) de las últimas N horas, para el gráfico.

        Se agrupa por los primeros 13 caracteres del timestamp ISO
        ("2026-07-27T21"), que es exactamente la hora: más barato que parsear
        fechas y funciona con el formato que ya se guarda.

        La ventana se corta por TIEMPO y no por cantidad de franjas. "Las
        últimas 24 franjas que existan" no es lo mismo: si el equipo estuvo
        apagado dos días, esas franjas vienen de días distintos y, como el
        gráfico muestra solo la hora, se ven horas repetidas y desordenadas.
        """
        desde = (datetime.now(timezone.utc) - timedelta(hours=horas)).isoformat()
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "SELECT substr(timestamp, 1, 13) AS hora, COUNT(*), "
                "       SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) "
                f"FROM queries WHERE timestamp >= ?{y_ademas} "
                "GROUP BY hora ORDER BY hora ASC",
                (desde, *params),
            )
            return [(h, total, bloq or 0) for h, total, bloq in cur.fetchall()]

    def top_dominios(
        self, limit: int = 10, solo_bloqueadas: bool = False, ocultar: bool = False,
    ) -> list[tuple[str, int]]:
        condiciones: list[str] = []
        params: list = []
        if solo_bloqueadas:
            condiciones.append("blocked = 1")
        filtro, params_ocultos = self._filtro_ocultos(ocultar)
        if filtro:
            condiciones.append(filtro)
            params += params_ocultos
        where = f"WHERE {' AND '.join(condiciones)}" if condiciones else ""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                f"SELECT domain, COUNT(*) c FROM queries {where} "
                "GROUP BY domain ORDER BY c DESC LIMIT ?",
                (*params, limit),
            )
            return cur.fetchall()

    def top_clientes(
        self, limit: int = 10, ocultar: bool = False, ordenar_por: str = "total",
    ) -> list[tuple[str, int, int]]:
        """Qué equipo de la red consulta más, y cuánto se le bloqueó.

        Es lo que un resolver puede decir y un proxy de una sola máquina no:
        si el resolver atiende a toda la casa, acá se ve qué dispositivo está
        generando el tráfico raro.

        `ordenar_por="bloqueadas"` da la otra lectura, que es la que importa
        para seguridad: el equipo que más consulta suele ser simplemente el que
        más se usa, mientras que el que más bloqueos junta es el que hay que ir
        a mirar. Son dos preguntas distintas y por eso se muestran las dos.
        """
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        orden = "bloqueadas DESC, c DESC" if ordenar_por == "bloqueadas" else "c DESC"
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "SELECT client_ip, COUNT(*) c, "
                "       SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) AS bloqueadas "
                f"FROM queries WHERE client_ip IS NOT NULL AND client_ip != ''{y_ademas} "
                f"GROUP BY client_ip ORDER BY {orden} LIMIT ?",
                (*params, limit),
            )
            return [(ip, total, bloq or 0) for ip, total, bloq in cur.fetchall()]

    def tipos_de_consulta(self, limit: int = 8, ocultar: bool = False) -> list[tuple[str, int]]:
        """Reparto por tipo de registro (A, AAAA, HTTPS, TXT...).

        No es decorativo: una proporción alta de TXT o de NULL es la firma
        más visible de tunneling por DNS, porque son los tipos que permiten
        meter datos arbitrarios en la respuesta. Acá solo se muestra el
        reparto; la detección en serio es otra cosa y va aparte.
        """
        filtro, params = self._filtro_ocultos(ocultar)
        where = f"WHERE {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                f"SELECT qtype, COUNT(*) c FROM queries {where} "
                "GROUP BY qtype ORDER BY c DESC LIMIT ?",
                (*params, limit),
            )
            return cur.fetchall()

    def latencia(self, ocultar: bool = False) -> dict:
        """Cuánto tarda en resolver, separando caché de consulta real.

        La separación no es un detalle: una respuesta desde caché tarda menos
        de un milisegundo y una que sale a internet tarda decenas. Promediarlas
        juntas da un número que baja cuanto más caché tenés y que no sirve para
        detectar nada. Lo que se quiere saber es cuánto tarda una consulta que
        SÍ tiene que salir: si eso se dispara, hay un problema con el upstream
        o con la red.

        `bloqueadas` tampoco entra en el promedio: bloquear es responder al
        instante, sin salir a ningún lado.
        """
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            fila = conn.execute(
                "SELECT COUNT(*), AVG(duration_ms), MIN(duration_ms), MAX(duration_ms) "
                "FROM queries WHERE blocked = 0 AND source != 'cache' "
                f"AND source != 'error'{y_ademas}",
                params,
            ).fetchone()
            desde_cache = conn.execute(
                f"SELECT COUNT(*), AVG(duration_ms) FROM queries WHERE source = 'cache'{y_ademas}",
                params,
            ).fetchone()
        muestras = fila[0] or 0
        return {
            "muestras": muestras,
            "promedio": float(fila[1] or 0.0),
            "minimo": float(fila[2] or 0.0),
            "maximo": float(fila[3] or 0.0),
            "cache_muestras": desde_cache[0] or 0,
            "cache_promedio": float(desde_cache[1] or 0.0),
        }

    def consolidar_dias(self) -> int:
        """Suma al resumen diario todo lo que todavía no estaba sumado.

        Devuelve cuántos días tocó.

        Se consolida por id y no por fecha: se toma todo lo que haya entrado
        desde la última vez, se agrupa por día y se SUMA a lo que ya había.
        Incluye el día de hoy, que después va a seguir creciendo y se va a
        volver a sumar en la próxima vuelta con lo nuevo.

        Ese "sumar" es la clave. Guardar el total del día pisando el anterior
        parece más simple pero se rompe con el recorte: si el historial se poda
        a media tarde, el recuento del día ya no incluye lo de la mañana y el
        resumen quedaría con menos de lo que realmente pasó.
        """
        with self._lock, closing(self._connect()) as conn, conn:
            fila = conn.execute(
                "SELECT valor FROM consolidacion WHERE clave = 'ultimo_id'"
            ).fetchone()
            ultimo = fila[0] if fila else 0
            nuevas = conn.execute(
                "SELECT substr(timestamp, 1, 10) AS dia, COUNT(*), "
                "       SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), "
                "       SUM(CASE WHEN source = 'cache' THEN 1 ELSE 0 END), "
                "       MAX(id) "
                "FROM queries WHERE id > ? GROUP BY dia",
                (ultimo,),
            ).fetchall()
            if not nuevas:
                return 0
            tope = ultimo
            for dia, total, bloqueadas, cacheadas, max_id in nuevas:
                conn.execute(
                    "INSERT INTO resumen_diario (fecha, total, bloqueadas, cacheadas) "
                    "VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(fecha) DO UPDATE SET "
                    "  total = total + excluded.total, "
                    "  bloqueadas = bloqueadas + excluded.bloqueadas, "
                    "  cacheadas = cacheadas + excluded.cacheadas",
                    (dia, total or 0, bloqueadas or 0, cacheadas or 0),
                )
                tope = max(tope, max_id or 0)
            conn.execute(
                "INSERT INTO consolidacion (clave, valor) VALUES ('ultimo_id', ?) "
                "ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor",
                (tope,),
            )
            conn.commit()
            return len(nuevas)

    def historico(self, dias: int = 30) -> list[tuple[str, int, int]]:
        """(fecha, total, bloqueadas) de los últimos N días.

        Combina las dos fuentes: lo ya consolidado en `resumen_diario`, que
        sobrevive al recorte del historial, más lo que entró después del
        marcador y todavía no se sumó. Sin esa segunda parte, lo de hoy no
        aparecería hasta la próxima consolidación.

        Solo se devuelven los días que realmente tienen datos: rellenar con
        ceros los días en que la máquina estuvo apagada haría parecer que el
        DNS dejó de funcionar.
        """
        ahora = datetime.now(timezone.utc)
        # `dias - 1` porque el día de hoy cuenta como uno: pidiendo 7 se
        # esperan 7 columnas, no 8.
        desde = (ahora - timedelta(days=max(0, dias - 1))).strftime("%Y-%m-%d")
        with self._lock, closing(self._connect()) as conn, conn:
            fila = conn.execute(
                "SELECT valor FROM consolidacion WHERE clave = 'ultimo_id'"
            ).fetchone()
            ultimo = fila[0] if fila else 0
            acumulado = {
                f: [t, b] for f, t, b in conn.execute(
                    "SELECT fecha, total, bloqueadas FROM resumen_diario "
                    "WHERE fecha >= ?",
                    (desde,),
                )
            }
            for dia, total, bloqueadas in conn.execute(
                "SELECT substr(timestamp, 1, 10) AS dia, COUNT(*), "
                "       SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) "
                "FROM queries WHERE id > ? AND substr(timestamp, 1, 10) >= ? "
                "GROUP BY dia",
                (ultimo, desde),
            ):
                actual = acumulado.setdefault(dia, [0, 0])
                actual[0] += total or 0
                actual[1] += bloqueadas or 0
        return [(f, v[0], v[1]) for f, v in sorted(acumulado.items())]

    def ritmo_de_bloqueos(self, horas_de_base: int = 6) -> dict:
        """Bloqueos del último minuto contra el ritmo habitual.

        El ritmo habitual se saca de las últimas horas y no de un número fijo:
        una casa con la lista de publicidad activada bloquea miles por día y
        otra sin ella bloquea decenas. Un umbral igual para las dos avisaría
        siempre a una y nunca a la otra.
        """
        ahora = datetime.now(timezone.utc)
        hace_un_minuto = (ahora - timedelta(minutes=1)).isoformat()
        desde = (ahora - timedelta(hours=horas_de_base)).isoformat()
        with self._lock, closing(self._connect()) as conn, conn:
            ultimo = conn.execute(
                "SELECT COUNT(*) FROM queries WHERE blocked = 1 AND timestamp >= ?",
                (hace_un_minuto,),
            ).fetchone()[0]
            fila = conn.execute(
                "SELECT COUNT(*), MIN(timestamp) FROM queries "
                "WHERE blocked = 1 AND timestamp >= ? AND timestamp < ?",
                (desde, hace_un_minuto),
            ).fetchone()
        base, primera = fila[0] or 0, fila[1]

        # Los minutos que la base REALMENTE cubre, no los de la ventana.
        #
        # Antes se dividía siempre por los 359 minutos de las 6 horas, aunque
        # el resolver llevara cuatro minutos prendido. Resultado: un resolver
        # con adblock que bloquea 60 por minuto de forma perfectamente
        # constante daba "0,5 por minuto habitual" y disparaba un aviso de
        # pico contra sí mismo durante la primera hora de cada arranque.
        minutos = horas_de_base * 60 - 1
        if primera:
            try:
                desde_real = datetime.fromisoformat(primera)
                if desde_real.tzinfo is None:
                    desde_real = desde_real.replace(tzinfo=timezone.utc)
                minutos = (ahora - timedelta(minutes=1) - desde_real).total_seconds() / 60
            except (TypeError, ValueError):
                pass
        # Menos de esto no es una línea de base, es ruido: se devuelve 0 y el
        # motor de alertas no dispara.
        if minutos < 10 or base == 0:
            return {"ultimo_minuto": ultimo, "por_minuto_habitual": 0.0}
        return {
            "ultimo_minuto": ultimo,
            "por_minuto_habitual": base / minutos,
        }

    def bloqueos_desde(self, ultimo_id: int) -> tuple[list[dict], int]:
        """Bloqueos registrados después de `ultimo_id`, y el id más alto visto.

        Se pagina por id y no por fecha para que el motor de alertas evalúe
        cada bloqueo exactamente una vez, sin depender de relojes ni de que
        dos consultas caigan en el mismo segundo.
        """
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                f"SELECT {', '.join(self.COLUMNAS)} FROM queries "
                "WHERE blocked = 1 AND id > ? ORDER BY id ASC LIMIT 500",
                (ultimo_id,),
            )
            filas = self._filas(cur)
            if len(filas) >= 500:
                # Se llenó la página: el próximo arranque tiene que seguir
                # desde la última fila devuelta y no desde el final de la
                # tabla, o se saltearían los bloqueos del medio.
                maximo = filas[-1]["id"]
            else:
                maximo = conn.execute(
                    "SELECT COALESCE(MAX(id), 0) FROM queries"
                ).fetchone()[0]
        return filas, max(ultimo_id, maximo)

    def dnssec(self, ocultar: bool = False) -> dict:
        """Cuántas respuestas vinieron validadas con DNSSEC.

        Solo se cuentan las que SALIERON a internet. Los bloqueos los responde
        este resolver y nunca están firmados; y los aciertos de caché son la
        misma respuesta contada muchas veces, así que un nombre sin firmar muy
        consultado hundía el porcentaje solo. Medido: con 1 firmada, 1 sin
        firmar y 998 aciertos de caché de la segunda, el panel mostraba 0,1%
        cuando lo real era 50%. Y como este mismo panel se jacta de tasas de
        caché altas, el número quedaba sistemáticamente mal.
        """
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            fila = conn.execute(
                "SELECT COUNT(*), SUM(dnssec) FROM queries "
                "WHERE blocked = 0 AND source NOT IN ('error', 'cache')"
                f"{y_ademas}",
                params,
            ).fetchone()
        total = fila[0] or 0
        firmadas = fila[1] or 0
        return {
            "total": total,
            "firmadas": firmadas,
            "sin_firmar": total - firmadas,
            "porcentaje": (firmadas / total * 100) if total else 0.0,
        }

    def top_paises(self, limit: int = 10, ocultar: bool = False) -> list[tuple[str, int]]:
        """Adónde apuntan los nombres que se resuelven, por país.

        Solo cuenta lo que tiene país resuelto: si la base local no está
        descargada, la lista sale vacía en vez de inventar un "desconocido"
        gigante que ocuparía el primer puesto y no diría nada.
        """
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "SELECT country, COUNT(*) c FROM queries "
                f"WHERE country IS NOT NULL AND country != ''{y_ademas} "
                "GROUP BY country ORDER BY c DESC LIMIT ?",
                (*params, limit),
            )
            return cur.fetchall()

    def top_proveedores(self, limit: int = 10, ocultar: bool = False) -> list[tuple[str, int]]:
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "SELECT provider, COUNT(*) c FROM queries "
                f"WHERE provider IS NOT NULL AND provider != ''{y_ademas} "
                "GROUP BY provider ORDER BY c DESC LIMIT ?",
                (*params, limit),
            )
            return cur.fetchall()

    def bloqueos_por_categoria(
        self, ocultar: bool = False, horas: int | None = None,
    ) -> list[tuple[str, int]]:
        """Cuántos bloqueos hubo de cada categoría, de mayor a menor.

        Es la diferencia entre "se bloquearon 143 consultas", que no dice nada,
        y "12 de malware, 3 de phishing, 128 de publicidad", que dice si tenés
        un problema o si simplemente estás filtrando anuncios.
        """
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        ventana = ""
        if horas is not None:
            ventana = " AND timestamp >= ?"
            params = [*params, (datetime.now(timezone.utc)
                                - timedelta(hours=horas)).isoformat()]
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "SELECT CASE WHEN category IS NULL OR category = '' THEN 'amenaza' "
                "            ELSE category END AS cat, COUNT(*) c "
                f"FROM queries WHERE blocked = 1{y_ademas}{ventana} "
                "GROUP BY cat ORDER BY c DESC",
                params,
            )
            return cur.fetchall()

    # Cuántos nombres distintos se traen de un grupo para medirles la entropía
    # y el largo. Con 200 el promedio ya es estable, y evita traer a memoria
    # decenas de miles de filas de un túnel que lleva horas corriendo.
    MUESTRA_POR_GRUPO = 200

    # Cuántos grupos candidatos se evalúan por vuelta. La consulta de
    # agregación es barata, pero medir entropía sí cuesta, así que se hace solo
    # sobre los que ya pasaron el filtro de volumen.
    MAX_GRUPOS = 40

    def tunneling(self, horas: int = 24, ocultar: bool = False) -> list[dict]:
        """Grupos (equipo + dominio padre) que parecen un túnel por DNS.

        Va en dos pasos a propósito. Primero una agregación en SQL, que es
        barata y descarta casi todo por volumen. Después, solo para los que
        quedaron, se traen hasta `MUESTRA_POR_GRUPO` nombres distintos y se les
        mide largo y entropía en Python, que es lo caro y lo que SQLite no
        sabe hacer.

        El filtro de ruido NO se aplica por defecto acá aunque el panel lo
        tenga prendido: ocultar telemetría es para que se vean las cosas raras,
        y sería absurdo que justamente esconda una detección.
        """
        desde = (datetime.now(timezone.utc) - timedelta(hours=horas)).isoformat()
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        marcas = ",".join("?" * len(TIPOS_DE_DATOS))

        with self._lock, closing(self._connect()) as conn, conn:
            candidatos = conn.execute(
                "SELECT client_ip, parent, COUNT(*) total, "
                "       COUNT(DISTINCT domain) distintos, "
                f"       SUM(CASE WHEN qtype IN ({marcas}) THEN 1 ELSE 0 END) tipos "
                "FROM queries "
                f"WHERE timestamp >= ? AND parent != ''{y_ademas} "
                "GROUP BY client_ip, parent "
                "HAVING total >= ? "
                "ORDER BY distintos DESC LIMIT ?",
                (*TIPOS_DE_DATOS, desde, *params, MINIMO_DE_CONSULTAS, self.MAX_GRUPOS),
            ).fetchall()

            grupos = []
            for cliente, padre, total, distintos, tipos in candidatos:
                nombres = [
                    n for (n,) in conn.execute(
                        "SELECT DISTINCT domain FROM queries "
                        "WHERE parent = ? AND client_ip = ? AND timestamp >= ? "
                        "LIMIT ?",
                        (padre, cliente, desde, self.MUESTRA_POR_GRUPO),
                    )
                ]
                variables = [parte_variable(n, padre) for n in nombres]
                variables = [v for v in variables if v]
                if variables:
                    largo = sum(len(v) for v in variables) / len(variables)
                    ent = sum(entropia(v) for v in variables) / len(variables)
                else:
                    largo = 0.0
                    ent = 0.0
                grupos.append({
                    "cliente": cliente,
                    "padre": padre,
                    "total": total,
                    "distintos": distintos,
                    "tipos_de_datos": tipos or 0,
                    "largo_promedio": largo,
                    "entropia_promedio": ent,
                })

        evaluados = [evaluar_grupo(g) for g in grupos]
        sospechosos = [g for g in evaluados if g["sospechoso"]]
        # Primero los que más señales juntaron, y a igualdad, los que más
        # nombres distintos generaron.
        sospechosos.sort(key=lambda g: (len(g["senales"]), g["distintos"]), reverse=True)
        return sospechosos

    def actividad_anomala(self, horas: int = 24, ocultar: bool = False) -> list[dict]:
        """Equipos cuya última hora se disparó respecto de su propia historia.

        La comparación es de cada equipo contra sí mismo: una tele consulta
        muchísimo menos que una notebook, así que un umbral fijo para todos
        marcaría siempre a la misma máquina.
        """
        desde = (datetime.now(timezone.utc) - timedelta(hours=horas)).isoformat()
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            filas = conn.execute(
                "SELECT client_ip, substr(timestamp, 1, 13) AS hora, COUNT(*) "
                "FROM queries "
                f"WHERE timestamp >= ? AND client_ip != ''{y_ademas} "
                "GROUP BY client_ip, hora ORDER BY client_ip, hora",
                (desde, *params),
            ).fetchall()

        # La franja de la hora EN CURSO. Antes se tomaba "la última franja que
        # exista", que no es lo mismo: un equipo que tuvo un pico hace catorce
        # horas y se apagó seguía apareciendo como "hizo 900 consultas en la
        # última hora" durante un día entero. El hallazgo era falso y encima
        # pegajoso.
        hora_actual = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")

        por_cliente: dict[str, list[tuple[str, int]]] = {}
        for cliente, hora, cuenta in filas:
            por_cliente.setdefault(cliente, []).append((hora, cuenta))

        resultado = []
        for cliente, horas_del_cliente in por_cliente.items():
            actual = next(
                (c for h, c in horas_del_cliente if h == hora_actual), 0
            )
            historia = [c for h, c in horas_del_cliente if h != hora_actual]
            if not historia:
                continue
            hallazgo = evaluar_actividad(cliente, actual, historia)
            if hallazgo:
                resultado.append(hallazgo)
        resultado.sort(key=lambda h: h["factor"], reverse=True)
        return resultado

    def bloqueos_por_motivo(self, limit: int = 10, ocultar: bool = False) -> list[tuple[str, int]]:
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "SELECT reason, COUNT(*) c FROM queries "
                f"WHERE blocked = 1 AND reason IS NOT NULL AND reason != ''{y_ademas} "
                "GROUP BY reason ORDER BY c DESC LIMIT ?",
                (*params, limit),
            )
            return cur.fetchall()
