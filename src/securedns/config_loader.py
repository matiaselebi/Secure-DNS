"""Carga la configuración desde config/config.yaml.

Los secretos NO viven acá: el token de Telegram sale de las variables de
entorno o del archivo `.env`, que está fuera de git. Un token en el
config.yaml es un token en el repositorio, y eso no se deshace con un commit.
"""

import os
from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dotenv es opcional
    def load_dotenv(*_a, **_k):
        return False

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass
class DnsConfig:
    host: str = "127.0.0.1"
    port: int = 53
    upstream_timeout: float = 2.0
    upstream_primary: str = "9.9.9.9"
    upstream_fallback: str = "1.1.1.1"
    min_cache_ttl: int = 30
    # "dot" = DNS-over-TLS (cifrado, puerto 853); "udp" = texto plano (puerto 53).
    upstream_mode: str = "dot"
    # Nombres para validar el certificado TLS de cada upstream (solo modo dot).
    upstream_primary_tls_name: str = "dns.quad9.net"
    upstream_fallback_tls_name: str = "cloudflare-dns.com"
    # Si ningún upstream respondió por TLS, ¿se permite caer a UDP plano?
    dot_fallback_to_udp: bool = True


@dataclass
class FilteringConfig:
    blocklist_path: str = "data/blocklist.txt"
    feeds_blocklist_path: str = "data/blocklist_feeds.txt"
    feeds_update_interval_hours: float = 6
    # Lista blanca manual: gana por sobre la blocklist. Misma convención que
    # en SecureProxy (mismo nombre de archivo/campo).
    allowlist_path: str = "data/allowlist.txt"
    # Categoría opcional (opt-in) de dominios de publicidad/tracking, aparte
    # de la blocklist de amenazas. Ver comentario en config.yaml.
    enable_ad_tracker_blocklist: bool = False
    ad_tracker_blocklist_path: str = "data/blocklist_adtracker.txt"
    # Con qué se le responde a un dominio bloqueado: "nxdomain" (no existe),
    # "zero" (0.0.0.0) o "localhost" (127.0.0.1). Ver dns_server.py.
    block_mode: str = "nxdomain"


@dataclass
class LoggingConfig:
    db_path: str = "data/dns_logs.db"
    # Tope de filas del historial. Un resolver que atiende a toda la casa
    # registra muchísimas consultas (cada página web dispara decenas), así
    # que sin tope el archivo crece para siempre y el panel deja de abrir.
    max_rows: int = 200_000


@dataclass
class IntelConfig:
    """Datos que se le piden a terceros. Todo apagado por defecto."""

    # Consultar por RDAP hace cuánto se registró un dominio. Ver rdap.py: cada
    # consulta le cuenta a un tercero qué dominio estás mirando, que es
    # justo lo que DoT evita, así que es opt-in explícito.
    rdap_enabled: bool = False
    rdap_cache_path: str = "data/rdap_cache.db"
    # Avisos por umbral (ver alertas.py). No avisa por cada bloqueo.
    alerts_enabled: bool = True
    telegram_enabled: bool = False
    # Base local de país/ASN. No sale a la red: se descarga una vez con
    # scripts/update_geoip.py y se consulta en disco.
    geoip_db_path: str = "data/geoip.db"


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"
    port: int = 8890
    # Filtro de VISTA: qué dominios tapan el panel. No cambia nada de lo que
    # se bloquea. Ver src/securedns/view_prefs.py.
    hide_noise: bool = True
    noisy_domains_path: str = "data/noisy_domains.txt"
    # Hallazgos de detección ya revisados y esperables en esta red (un CDN de
    # video tiene la misma forma que un túnel). Silencia el hallazgo y su
    # descuento de puntaje; NO cambia ninguna decisión de bloqueo.
    # Ver src/securedns/hallazgos.py.
    normal_findings_path: str = "data/deteccion_normales.txt"


@dataclass
class Config:
    dns: DnsConfig = field(default_factory=DnsConfig)
    filtering: FilteringConfig = field(default_factory=FilteringConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    intel: IntelConfig = field(default_factory=IntelConfig)
    # Salen del entorno o del .env, nunca del YAML.
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    def resolve_path(self, relative_path: str) -> Path:
        path = Path(relative_path)
        if path.is_absolute():
            return path
        return PROJECT_ROOT / path


def _seccion(clase, raw: dict, nombre: str):
    """Arma una sección de la configuración sin morir por un YAML imperfecto.

    Dos casos que hacían fallar el arranque con un traceback pelado, y que son
    los dos fáciles de provocar editando el archivo a mano:

    - Una sección presente pero con todo comentado. YAML devuelve `None`, no
      `{}`, y `Clase(**None)` explota.
    - Una clave que ya no existe o está mal escrita. `Clase(**{...})` tira un
      TypeError sin decir en qué sección está el problema.

    Las claves desconocidas se avisan y se ignoran, en vez de impedir que el
    resolver arranque: quedarse sin DNS por una línea de más en el config es
    una reacción desproporcionada.
    """
    datos = raw.get(nombre) or {}
    if not isinstance(datos, dict):
        print(f"[SecureDNS] la sección '{nombre}' del config.yaml no es un mapa; se ignora")
        return clase()
    validas = {campo.name for campo in fields(clase)}
    sobrantes = set(datos) - validas
    for clave in sorted(sobrantes):
        print(f"[SecureDNS] config.yaml: '{nombre}.{clave}' no existe, se ignora")
    return clase(**{k: v for k, v in datos.items() if k in validas})


def load_config(config_path: str | None = None) -> Config:
    if config_path is None:
        config_path = str(PROJECT_ROOT / "config" / "config.yaml")

    raw: dict = {}
    if Path(config_path).exists():
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

    load_dotenv(PROJECT_ROOT / ".env")

    return Config(
        telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN", ""),
        telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID", ""),
        dns=_seccion(DnsConfig, raw, "dns"),
        filtering=_seccion(FilteringConfig, raw, "filtering"),
        logging=_seccion(LoggingConfig, raw, "logging"),
        dashboard=_seccion(DashboardConfig, raw, "dashboard"),
        intel=_seccion(IntelConfig, raw, "intel"),
    )
