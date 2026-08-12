"""Leer las consultas de Pi-hole y traerlas a la base de SecureDNS.

QUÉ SE SALVA CON ESTO, QUE ES DE LO QUE SE TRATA LA FASE 3

Pi-hole resuelve y bloquea mejor de lo que va a resolver y bloquear nunca un
resolutor casero. Lo que Pi-hole NO hace es lo que hace valioso a este
proyecto: detectar túneles de DNS por la forma del tráfico, categorizar de
dónde salió cada bloqueo, dejar que alguien marque un hallazgo como normal, y
convertir todo eso en un puntaje que se pueda auditar.

Todo eso ya está escrito, probado, y funciona sobre la tabla `queries` de
SecureDNS. Así que el trabajo de esta fase no es reescribir la detección para
que hable el idioma de Pi-hole: es traer las consultas de Pi-hole a la tabla
que la detección ya sabe leer. Cero líneas tocadas en `deteccion.py`, en
`hallazgos.py` y en `puntaje.py`.

Y se gana algo que antes no existía: Pi-hole atiende a TODA la casa. Hasta
ahora la detección de túneles miraba una sola máquina, la que corría el
resolutor. Ahora mira el teléfono, la tele y la notebook de al lado, cada uno
con su IP, que es justo lo que `evaluar_grupo` necesita para agrupar por
(equipo, dominio padre).

POR QUÉ SE COPIA EN VEZ DE CONSULTAR LA BASE DE PI-HOLE DIRECTO

Porque no es una copia: es un enriquecido. A cada fila se le agrega lo que
Pi-hole no tiene y nosotros sí: el dominio padre precalculado (sin eso, la
detección de túneles hace un scan completo en cada refresco del panel), la
categoría cruzada contra nuestras propias listas, y la marca de ruido. Además
Pi-hole poda su historial con su propio criterio, y las consultas ya
importadas sobreviven a esa poda.

LA REGLA QUE NO SE ROMPE: SOLO LECTURA

`pihole-FTL.db` se abre con `mode=ro` y no se le escribe jamás. La escribe un
proceso ajeno que no sabe que existimos. Todo el estado de la importación
(hasta qué fila se leyó) vive de nuestro lado.

DE DÓNDE SALEN LOS NÚMEROS DE ESTADO

De la documentación de Pi-hole, que publica la estructura de esta base y la
tabla de códigos. Un código que no esté en ninguna de las dos listas es uno
que Pi-hole agregó después de que esto se escribió: no se adivina, se cuenta
aparte y se avisa.
"""

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .deteccion import dominio_padre

# Estados que significan "bloqueado" y "resuelto", según la documentación.
BLOQUEADAS = frozenset({1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18})
PERMITIDAS = frozenset({2, 3, 12, 13, 14, 17})

# Cuál de los estados permitidos salió de la caché de Pi-hole. Importa porque
# las estadísticas de SecureDNS cuentan los aciertos de caché mirando
# `source = 'cache'`: si todo entrara como consulta resuelta, el panel diría
# que la caché no sirve para nada.
CACHE = frozenset({3, 17})

MOTIVOS = {
    1: "está en gravity (alguna de las listas)",
    4: "coincide con una expresión de la lista negra",
    5: "está en la lista negra exacta",
    6: "lo bloqueó el servidor de arriba",
    7: "lo bloqueó el servidor de arriba",
    8: "lo bloqueó el servidor de arriba",
    9: "bloqueado al seguir el CNAME",
    10: "bloqueado al seguir el CNAME",
    11: "bloqueado al seguir el CNAME",
    15: "bloqueado porque su base estaba ocupada",
    16: "dominio especial",
    18: "lo bloqueó el servidor de arriba (EDE 15)",
}

# Los tipos de consulta, por número. La detección de túneles mira justamente
# la proporción de TXT y NULL, así que traducir mal esto la dejaría ciega.
TIPOS = {
    1: "A", 2: "AAAA", 3: "ANY", 4: "SRV", 5: "SOA", 6: "PTR", 7: "TXT",
    8: "NAPTR", 9: "MX", 10: "DS", 11: "RRSIG", 12: "DNSKEY", 13: "NS",
    14: "OTHER", 15: "SVCB", 16: "HTTPS",
}

# Cuántas filas se traen por vuelta. Con una casa activa Pi-hole registra
# decenas de miles de consultas por día; sin tope, la primera importación
# levantaría meses de historial de una sentada.
POR_VUELTA = 20_000

RUTA_POR_DEFECTO = "/etc/pihole/pihole-FTL.db"


def tipo_de(codigo) -> str:
    """El nombre del tipo de consulta. Los tipos raros vienen con +100 de
    corrimiento, según la documentación, y ahí no se inventa: van como OTHER."""
    try:
        numero = int(codigo or 0)
    except (TypeError, ValueError):
        return "OTHER"
    return TIPOS.get(numero, "OTHER")


def a_iso(epoch) -> str:
    """De la marca de tiempo de Pi-hole (epoch) a la de SecureDNS (ISO en UTC).

    Esto no es cosmética. La tabla de SecureDNS guarda el tiempo como texto y
    ordena por texto: si se metieran epochs crudos, todas las filas importadas
    quedarían ordenadas ANTES o DESPUÉS de todo lo demás para siempre, porque
    "1785..." y "2026-..." no se comparan como fechas. Es exactamente el bug
    que ya apareció una vez en la línea de tiempo de SecureCenter.
    """
    try:
        return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return datetime.now(timezone.utc).isoformat()


class MarcaDeAgua:
    """Hasta qué fila de Pi-hole se leyó. Vive de nuestro lado, en un JSON.

    Un archivo y no una tabla nueva porque SecureDNS ya guarda así otros
    estados chicos (el DNS anterior, las preferencias de vista, los hallazgos
    marcados como normales), y porque agregar una tabla obliga a una migración
    para guardar un solo número.
    """

    def __init__(self, ruta):
        self.ruta = Path(ruta)

    def leer(self) -> int:
        try:
            return int(json.loads(self.ruta.read_text(encoding="utf-8"))["ultimo_id"])
        except (OSError, ValueError, KeyError, TypeError):
            return 0

    def guardar(self, ultimo_id: int) -> None:
        self.ruta.parent.mkdir(parents=True, exist_ok=True)
        self.ruta.write_text(
            json.dumps({"ultimo_id": int(ultimo_id)}), encoding="utf-8")


def _conectar(ruta):
    """Solo lectura, siempre. `mode=ro` no es una sugerencia: con `uri=True`
    SQLite se niega a escribir aunque el archivo tenga permiso."""
    return sqlite3.connect(f"file:{ruta}?mode=ro", uri=True, timeout=5.0)


def maximo_id(ruta) -> int:
    try:
        with closing(_conectar(ruta)) as con:
            fila = con.execute("SELECT MAX(id) FROM queries").fetchone()
        return int(fila[0] or 0)
    except sqlite3.Error:
        return 0


def leer_nuevas(ruta, desde_id: int, limite: int = POR_VUELTA) -> tuple[list, int]:
    """Las consultas posteriores a `desde_id`. Devuelve (filas, último id).

    Se pide `id > ?` y no un rango de fechas porque el id es autoincremental y
    no se repite: filtrando por fecha, dos importaciones seguidas dentro del
    mismo segundo traerían las mismas filas dos veces.
    """
    try:
        with closing(_conectar(ruta)) as con:
            con.row_factory = sqlite3.Row
            filas = con.execute(
                "SELECT id, timestamp, type, status, domain, client, reply_time "
                "FROM queries WHERE id > ? ORDER BY id LIMIT ?",
                (int(desde_id), int(limite)),
            ).fetchall()
    except sqlite3.Error as exc:
        print(f"[SecureDNS] no pude leer la base de Pi-hole: {exc}")
        return [], desde_id
    if not filas:
        return [], desde_id
    return filas, int(filas[-1]["id"])


def traducir(filas, categoria_de=None, es_ruido=None) -> tuple[list, set]:
    """De las filas de Pi-hole a las filas de SecureDNS. Devuelve (filas, raros).

    `categoria_de` es lo que convierte esto en algo nuestro y no en una copia:
    es la función que dice de qué es un dominio según NUESTRAS listas. Pi-hole
    sabe que bloqueó; no sabe si fue malware, phishing o publicidad, porque
    gravity mezcla todas las listas en una sola bolsa.
    """
    salida = []
    desconocidos: set = set()
    for f in filas:
        estado = int(f["status"] or 0)
        if estado not in BLOQUEADAS and estado not in PERMITIDAS:
            # Estado nuevo o "todavía sin determinar" (el 0). No se adivina:
            # meterlo como resuelto ensucia las estadísticas y meterlo como
            # bloqueado inventa un bloqueo que nadie hizo.
            desconocidos.add(estado)
            continue
        bloqueada = estado in BLOQUEADAS
        dominio = (f["domain"] or "").strip().lower()
        if not dominio:
            continue
        categoria = ""
        if bloqueada and categoria_de is not None:
            categoria = categoria_de(dominio) or ""
        salida.append({
            "timestamp": a_iso(f["timestamp"]),
            "client_ip": (f["client"] or "").strip(),
            "domain": dominio,
            "qtype": tipo_de(f["type"]),
            "blocked": 1 if bloqueada else 0,
            "reason": MOTIVOS.get(estado, "") if bloqueada else "",
            # 'pihole' como origen para que SecureCenter no cuente dos veces
            # el mismo bloqueo: él también lee la base de Pi-hole directo.
            "source": "cache" if estado in CACHE else "pihole",
            "duration_ms": float(f["reply_time"] or 0.0) * 1000.0,
            "noisy": 1 if (es_ruido is not None and es_ruido(dominio)) else 0,
            "category": categoria,
            "parent": dominio_padre(dominio),
        })
    return salida, desconocidos


def importar(cfg, logger, ruta=None, limite: int = POR_VUELTA,
             categoria_de=None, es_ruido=None) -> dict:
    """Una vuelta de importación. Nunca lanza; devuelve un informe.

    `categoria_de` y `es_ruido` se pasan de afuera en vez de sacarlos del
    logger porque son de otra capa: la categoría la sabe la blocklist y el
    ruido lo sabe el archivo de preferencias del panel. El logger solo
    escribe. Quien llama arma las dos y las pasa; en los tests van directo.

    El informe siempre tiene `ok` y `detalle`. Que no sea un booleano es para
    que el panel pueda explicar por qué no importó nada, que es el caso
    interesante.
    """
    conf = getattr(cfg, "pihole", None)
    if conf is None or not conf.habilitado:
        return {"ok": True, "importadas": 0, "salteado": True,
                "detalle": "Pi-hole desactivado en el config"}

    ruta = ruta or conf.base_consultas or RUTA_POR_DEFECTO
    if not Path(ruta).exists():
        return {"ok": False, "importadas": 0,
                "detalle": (f"no encuentro la base de Pi-hole en {ruta}. "
                            "Si Pi-hole está en otra máquina, esto hay que "
                            "correrlo allá: la base no se lee por red")}

    marca = MarcaDeAgua(cfg.resolve_path(conf.marca_de_agua))
    desde = marca.leer()

    # Si Pi-hole recreó su base (una reinstalación, un borrado del historial),
    # los ids arrancan de cero otra vez y nuestra marca queda adelante de todo.
    # Sin esta comprobación no volvería a importar nunca más, en silencio.
    tope = maximo_id(ruta)
    if tope and desde > tope:
        print(f"[SecureDNS] la base de Pi-hole arrancó de nuevo "
              f"(mi marca era {desde} y su último id es {tope}); "
              "vuelvo a empezar desde ahí")
        desde = 0

    filas, ultimo = leer_nuevas(ruta, desde, limite)
    if not filas:
        return {"ok": True, "importadas": 0,
                "detalle": "no hay consultas nuevas en Pi-hole"}

    traducidas, desconocidos = traducir(
        filas, categoria_de=categoria_de, es_ruido=es_ruido)
    guardadas = logger.importar_consultas(traducidas)
    marca.guardar(ultimo)

    detalle = f"{guardadas} consultas de Pi-hole importadas (hasta el id {ultimo})"
    if desconocidos:
        detalle += (f"; salteé {len(desconocidos)} estado(s) que no conozco "
                    f"({sorted(desconocidos)})")
    return {"ok": True, "importadas": guardadas, "ultimo_id": ultimo,
            "desconocidos": sorted(desconocidos), "detalle": detalle}
