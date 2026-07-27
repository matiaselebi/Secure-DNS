#!/usr/bin/env python3
"""Punto de entrada: levanta el resolver DNS + el dashboard web."""

import os
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

PID_FILE = PROJECT_ROOT / "data" / "dns.pid"

# Misma idea que en SecureProxy: releer blocklist/allowlist desde disco cada
# pocos segundos (liviano, son archivos de texto chicos), separado del ciclo
# pesado de descarga de feeds (horas). Así un dominio agregado a mano
# (editando el .txt, desde el menú .bat, o por otro medio que no sea el
# propio dashboard) se aplica solo, sin reiniciar el proceso.
LIGHT_RELOAD_INTERVAL_SECONDS = 15

import update_blocklist  # noqa: E402
from securedns.blocklist import Allowlist, Blocklist  # noqa: E402
from securedns.config_loader import load_config  # noqa: E402
from securedns.dashboard import build_dashboard_server  # noqa: E402
from securedns.dns_server import ThreatIntelResolver, build_dns_server  # noqa: E402
from securedns.logger_db import LoggerDB  # noqa: E402


def _update_feeds_in_background(
    min_interval_hours: float, blocklist: Blocklist, include_ad_tracker: bool = False
) -> None:
    try:
        updated = update_blocklist.main(
            force=False, min_interval_hours=min_interval_hours, include_ad_tracker=include_ad_tracker
        )
        if updated:
            blocklist.reload()
            print("[SecureDNS] lista de amenazas actualizada y recargada en caliente.")
    except Exception as exc:  # noqa: BLE001
        print(f"[SecureDNS] no se pudo actualizar la blocklist automática: {exc}")


def _light_reload_loop(blocklist: Blocklist, allowlist: Allowlist) -> None:
    while True:
        time.sleep(LIGHT_RELOAD_INTERVAL_SECONDS)
        try:
            blocklist.reload()
            allowlist.reload()
        except Exception as exc:  # noqa: BLE001 - no debe tumbar el resolver por esto
            print(f"[SecureDNS] error recargando listas: {exc}")


def main() -> None:
    cfg = load_config()

    blocklist_paths = [
        str(cfg.resolve_path(cfg.filtering.blocklist_path)),
        str(cfg.resolve_path(cfg.filtering.feeds_blocklist_path)),
    ]
    if cfg.filtering.enable_ad_tracker_blocklist:
        blocklist_paths.append(str(cfg.resolve_path(cfg.filtering.ad_tracker_blocklist_path)))
    blocklist = Blocklist(blocklist_paths)
    allowlist = Allowlist(str(cfg.resolve_path(cfg.filtering.allowlist_path)))
    logger_db = LoggerDB(str(cfg.resolve_path(cfg.logging.db_path)))

    resolver = ThreatIntelResolver(
        blocklist=blocklist,
        logger_db=logger_db,
        upstream_primary=cfg.dns.upstream_primary,
        upstream_fallback=cfg.dns.upstream_fallback,
        upstream_timeout=cfg.dns.upstream_timeout,
        min_cache_ttl=cfg.dns.min_cache_ttl,
        allowlist=allowlist,
        upstream_mode=cfg.dns.upstream_mode,
        upstream_primary_tls_name=cfg.dns.upstream_primary_tls_name,
        upstream_fallback_tls_name=cfg.dns.upstream_fallback_tls_name,
        dot_fallback_to_udp=cfg.dns.dot_fallback_to_udp,
    )

    dns_server = build_dns_server(cfg.dns.host, cfg.dns.port, resolver)
    dashboard_server = build_dashboard_server(
        cfg.dashboard.host, cfg.dashboard.port, logger_db, allowlist, blocklist, resolver
    )

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))

    print(f"[SecureDNS] resolver escuchando en {cfg.dns.host}:{cfg.dns.port} (UDP)")
    if cfg.dns.upstream_mode == "dot":
        modo = "DNS-over-TLS (cifrado, puerto 853)"
        if cfg.dns.dot_fallback_to_udp:
            modo += " con respaldo UDP plano"
    else:
        modo = "UDP texto plano (puerto 53)"
    print(f"[SecureDNS] modo upstream: {modo}")
    print(f"[SecureDNS] upstream primario: {cfg.dns.upstream_primary} (Quad9)")
    print(f"[SecureDNS] upstream de respaldo: {cfg.dns.upstream_fallback} (Cloudflare)")
    print(f"[SecureDNS] dashboard: http://{cfg.dashboard.host}:{cfg.dashboard.port}/")
    print(f"[SecureDNS] logs: {cfg.resolve_path(cfg.logging.db_path)}")
    print(f"[SecureDNS] PID: {os.getpid()} (guardado en {PID_FILE})")
    print("[SecureDNS] Ctrl+C para detener (o 'python scripts/stop_dns.py' si corre en segundo plano).")

    update_thread = threading.Thread(
        target=_update_feeds_in_background,
        args=(cfg.filtering.feeds_update_interval_hours, blocklist, cfg.filtering.enable_ad_tracker_blocklist),
        daemon=True,
    )
    update_thread.start()

    dashboard_thread = threading.Thread(target=dashboard_server.serve_forever, daemon=True)
    dashboard_thread.start()

    light_reload_thread = threading.Thread(
        target=_light_reload_loop, args=(blocklist, allowlist), daemon=True
    )
    light_reload_thread.start()

    dns_server.start_thread()
    try:
        while dns_server.isAlive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[SecureDNS] deteniendo...")
    finally:
        dns_server.stop()
        dashboard_server.shutdown()
        if PID_FILE.exists():
            PID_FILE.unlink()


if __name__ == "__main__":
    main()
