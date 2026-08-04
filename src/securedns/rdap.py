"""Edad de un dominio, consultada por RDAP.

POR QUÉ IMPORTA LA EDAD

Muchísimo malware usa dominios registrados hace días. Un sitio de phishing vive
unas horas: se registra, se manda la campaña, y se quema antes de que entre en
ningún feed. Por eso "este dominio tiene 3 días" es una señal más fuerte que
casi cualquier lista, y es de las pocas que sirve contra algo que nadie vio
todavía.

POR QUÉ RDAP Y NO WHOIS

RDAP es el reemplazo moderno y estandarizado de WHOIS: responde JSON, se
consulta por HTTPS, y no hay que parsear texto libre distinto para cada
registrador. `rdap.org` redirige a la autoridad que corresponda según el TLD.

POR QUÉ ESTÁ APAGADO POR DEFECTO

Acá hay una contradicción que conviene decir en voz alta en vez de esconderla:
**cada consulta RDAP le cuenta a un tercero qué dominio estás mirando**. Este
proyecto puso DNS-over-TLS justamente para que tu proveedor de internet no
pueda ver eso. Sería incoherente activar por defecto algo que se lo cuenta a
otro.

Por eso:

1. Viene apagado (`intel.rdap_enabled: false`).
2. No se consulta para todo lo que se resuelve, ni cerca: solo para los pocos
   dominios que **ya llamaron la atención** por otra razón, que hoy son los
   hallazgos de la pestaña Detección.
3. Lo que se averigua se guarda en disco 30 días, así que el mismo dominio no
   se pregunta dos veces.
4. Hay un tope de consultas nuevas por vuelta, para que un día raro no dispare
   cuarenta pedidos salientes de golpe.

Y falla hacia adelante: si RDAP no responde, no está la fecha, o el TLD no
tiene servidor RDAP (pasa con varios ccTLD, incluido `.ar`), no pasa nada. El
panel muestra el hallazgo sin la edad en vez de romperse.
"""

import json
import sqlite3
import threading
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import requests

# rdap.org redirige al servidor de la autoridad que corresponda según el TLD.
# Usarlo evita tener que mantener el mapa de TLD a servidor RDAP, que cambia.
SERVICIO = "https://rdap.org/domain/"

# Corto a propósito: esto corre mientras se arma una página. Si el servidor
# RDAP está lento, es preferible mostrar el hallazgo sin la edad que dejar el
# panel colgado.
TIMEOUT = 4.0

# 30 días. La fecha de registro de un dominio no cambia; lo único que cambia
# es la de expiración, que acá no se usa para nada.
TTL_CACHE = 30 * 24 * 3600

# Un dominio registrado hace menos que esto se marca. Treinta días es el
# número que usa casi toda la industria para "recién registrado".
DIAS_SOSPECHOSO = 30

# Si el servicio falla varias veces seguidas, se deja de intentar por un rato.
# Sin esto, con RDAP caído cada refresco del panel se comería el timeout de
# cada dominio, uno por uno.
FALLOS_PARA_FRENAR = 3
FRENO_SEGUNDOS = 300


class ClienteRDAP:
    """Averigua hace cuánto se registró un dominio, con cache en disco."""

    def __init__(self, enabled: bool, cache_path: str):
        self.enabled = enabled
        self.cache_path = cache_path
        self._lock = threading.Lock()
        self._fallos = 0
        self._frenado_hasta = 0.0
        Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.cache_path, check_same_thread=False)

    def _init_schema(self) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dominios (
                    dominio TEXT PRIMARY KEY,
                    registrado TEXT,
                    consultado_en REAL NOT NULL,
                    error TEXT
                )
                """
            )
            conn.commit()

    # ---------- cache ----------

    def _leer_cache(self, dominio: str) -> dict | None:
        with self._lock, closing(self._connect()) as conn, conn:
            fila = conn.execute(
                "SELECT registrado, consultado_en, error FROM dominios WHERE dominio = ?",
                (dominio,),
            ).fetchone()
        if fila is None:
            return None
        registrado, consultado_en, error = fila
        if time.time() - consultado_en > TTL_CACHE:
            return None
        return {"registrado": registrado, "error": error}

    def _guardar_cache(self, dominio: str, registrado: str | None, error: str) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT OR REPLACE INTO dominios (dominio, registrado, consultado_en, error) "
                "VALUES (?, ?, ?, ?)",
                (dominio, registrado, time.time(), error),
            )
            conn.commit()

    # ---------- consulta ----------

    @staticmethod
    def _fecha_de_registro(datos: dict) -> str | None:
        """Saca la fecha de registro de la respuesta RDAP.

        RDAP devuelve una lista de eventos con su tipo. El que interesa es
        `registration`. Se busca por nombre y no por posición porque el orden
        no está garantizado y cada registrador manda los suyos.
        """
        for evento in datos.get("events") or []:
            if str(evento.get("eventAction", "")).lower() == "registration":
                fecha = evento.get("eventDate")
                if fecha:
                    return str(fecha)
        return None

    def _consultar(self, dominio: str) -> tuple[str | None, str]:
        try:
            respuesta = requests.get(
                SERVICIO + dominio,
                timeout=TIMEOUT,
                headers={"Accept": "application/rdap+json"},
            )
        except requests.RequestException as exc:
            return None, f"no se pudo consultar: {type(exc).__name__}"
        if respuesta.status_code == 404:
            # Que no esté en RDAP no es un error del servicio: hay TLD sin
            # servidor RDAP público (varios ccTLD, incluido .ar).
            return None, "el TLD no publica RDAP o el dominio no existe"
        if respuesta.status_code != 200:
            return None, f"el servicio respondió {respuesta.status_code}"
        try:
            datos = respuesta.json()
        except (ValueError, json.JSONDecodeError):
            return None, "la respuesta no era JSON"
        fecha = self._fecha_de_registro(datos)
        if fecha is None:
            return None, "la respuesta no traía fecha de registro"
        return fecha, ""

    def edad(self, dominio: str, permitir_red: bool = True) -> dict | None:
        """Hace cuánto se registró el dominio.

        Devuelve `{"dias": N, "reciente": bool, "fecha": "..."}`, o None si no
        se pudo averiguar (apagado, sin cache y sin permiso de salir, servicio
        caído, TLD sin RDAP). Nunca lanza: esto corre mientras se arma una
        página y no puede tumbarla.
        """
        dominio = (dominio or "").strip().lower().strip(".")
        if not self.enabled or not dominio:
            return None

        guardado = self._leer_cache(dominio)
        if guardado is None:
            if not permitir_red or self._frenado():
                return None
            fecha, error = self._consultar(dominio)
            self._anotar_resultado(error)
            self._guardar_cache(dominio, fecha, error)
            guardado = {"registrado": fecha, "error": error}

        if not guardado.get("registrado"):
            return None
        return self._a_edad(guardado["registrado"])

    @staticmethod
    def _a_edad(fecha_iso: str) -> dict | None:
        try:
            # RDAP usa ISO 8601, a veces con Z en vez de +00:00.
            momento = datetime.fromisoformat(str(fecha_iso).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        if momento.tzinfo is None:
            momento = momento.replace(tzinfo=timezone.utc)
        dias = (datetime.now(timezone.utc) - momento).days
        if dias < 0:
            return None
        return {
            "dias": dias,
            "reciente": dias < DIAS_SOSPECHOSO,
            "fecha": momento.strftime("%d/%m/%Y"),
        }

    # ---------- freno ----------

    def _frenado(self) -> bool:
        with self._lock:
            return time.time() < self._frenado_hasta

    def _anotar_resultado(self, error: str) -> None:
        with self._lock:
            if error and "no se pudo consultar" in error:
                self._fallos += 1
                if self._fallos >= FALLOS_PARA_FRENAR:
                    self._frenado_hasta = time.time() + FRENO_SEGUNDOS
                    self._fallos = 0
            else:
                # Un 404 no es una falla del servicio: es una respuesta.
                self._fallos = 0
