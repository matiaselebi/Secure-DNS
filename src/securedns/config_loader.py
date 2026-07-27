"""Carga la configuración desde config/config.yaml."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml

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


@dataclass
class LoggingConfig:
    db_path: str = "data/dns_logs.db"


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"
    port: int = 8890


@dataclass
class Config:
    dns: DnsConfig = field(default_factory=DnsConfig)
    filtering: FilteringConfig = field(default_factory=FilteringConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)

    def resolve_path(self, relative_path: str) -> Path:
        path = Path(relative_path)
        if path.is_absolute():
            return path
        return PROJECT_ROOT / path


def load_config(config_path: str | None = None) -> Config:
    if config_path is None:
        config_path = str(PROJECT_ROOT / "config" / "config.yaml")

    raw: dict = {}
    if Path(config_path).exists():
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

    return Config(
        dns=DnsConfig(**raw.get("dns", {})),
        filtering=FilteringConfig(**raw.get("filtering", {})),
        logging=LoggingConfig(**raw.get("logging", {})),
        dashboard=DashboardConfig(**raw.get("dashboard", {})),
    )
