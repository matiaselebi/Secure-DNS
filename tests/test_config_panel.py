"""Tests de la pestaña Configuracion del dashboard de SecureDNS."""

import shutil
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

import securedns.config_loader as cl  # noqa: E402
from securedns.config_writer import read_value, set_value  # noqa: E402


@pytest.fixture
def config_temporal(tmp_path):
    destino = tmp_path / "config.yaml"
    shutil.copy(RAIZ / "config" / "config.yaml", destino)
    return destino


def test_escribir_no_borra_comentarios(config_temporal):
    original = config_temporal.read_text(encoding="utf-8")
    assert set_value(config_temporal, "dns", "upstream_mode", "udp")
    nuevo = config_temporal.read_text(encoding="utf-8")
    assert [l for l in original.splitlines() if l.strip().startswith("#")] == \
           [l for l in nuevo.splitlines() if l.strip().startswith("#")]
    assert read_value(config_temporal, "dns", "upstream_mode") == "udp"


def _dashboard(tmp_path, monkeypatch):
    from securedns.blocklist import Allowlist, Blocklist
    from securedns.dashboard import build_dashboard_server
    from securedns.dns_server import ThreatIntelResolver
    from securedns.logger_db import LoggerDB

    (tmp_path / "config").mkdir(exist_ok=True)
    shutil.copy(RAIZ / "config" / "config.yaml", tmp_path / "config" / "config.yaml")
    monkeypatch.setattr(cl, "PROJECT_ROOT", tmp_path)

    for nombre in ("b.txt", "a.txt"):
        (tmp_path / nombre).write_text("")
    blocklist = Blocklist(str(tmp_path / "b.txt"))
    allowlist = Allowlist(str(tmp_path / "a.txt"))
    logger = LoggerDB(str(tmp_path / "l.db"))
    resolver = ThreatIntelResolver(
        blocklist=blocklist, logger_db=logger,
        upstream_primary="9.9.9.9", upstream_fallback="1.1.1.1",
        allowlist=allowlist, upstream_mode="dot",
        dot_fallback_to_udp=True, min_cache_ttl=30,
    )
    server = build_dashboard_server("127.0.0.1", 0, logger, allowlist, blocklist, resolver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    return base, resolver, server, tmp_path / "config" / "config.yaml"


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.read().decode("utf-8", "replace")


def test_cambiar_transporte_en_caliente(tmp_path, monkeypatch):
    """Pasar de DoT a texto plano y volver, sin reiniciar el resolver."""
    base, resolver, server, cfg = _dashboard(tmp_path, monkeypatch)
    try:
        _get(f"{base}/config?k=upstream_mode&v=udp")
        assert resolver.upstream_mode == "udp"
        assert read_value(cfg, "dns", "upstream_mode") == "udp"

        _get(f"{base}/config?k=upstream_mode&v=dot")
        assert resolver.upstream_mode == "dot"
    finally:
        server.shutdown()


def test_cambiar_fallback_y_ttl_en_caliente(tmp_path, monkeypatch):
    base, resolver, server, cfg = _dashboard(tmp_path, monkeypatch)
    try:
        _get(f"{base}/config?k=dot_fallback_to_udp&v=0")
        assert resolver.dot_fallback_to_udp is False
        assert read_value(cfg, "dns", "dot_fallback_to_udp") is False

        _get(f"{base}/config?k=min_cache_ttl&v=120")
        assert resolver.min_cache_ttl == 120
    finally:
        server.shutdown()


def test_ads_se_guarda_aunque_no_se_aplique_en_vivo(tmp_path, monkeypatch):
    """Esta opcion necesita reiniciar (hay que descargar el feed): se persiste
    igual, y la pagina avisa que requiere reinicio."""
    base, _resolver, server, cfg = _dashboard(tmp_path, monkeypatch)
    try:
        _get(f"{base}/config?k=enable_ad_tracker_blocklist&v=1")
        assert read_value(cfg, "filtering", "enable_ad_tracker_blocklist") is True
        assert "Requiere reiniciar" in _get(f"{base}/")
    finally:
        server.shutdown()


def test_valores_invalidos_no_cambian_nada(tmp_path, monkeypatch):
    base, resolver, server, _cfg = _dashboard(tmp_path, monkeypatch)
    try:
        _get(f"{base}/config?k=upstream_mode&v=inventado")
        assert resolver.upstream_mode == "dot"
        _get(f"{base}/config?k=min_cache_ttl&v=-5")
        _get(f"{base}/config?k=min_cache_ttl&v=hola")
        assert resolver.min_cache_ttl == 30
        _get(f"{base}/config?k=clave_no_listada&v=1")
        assert resolver.upstream_mode == "dot"
    finally:
        server.shutdown()


def test_el_panel_refleja_el_estado_real(tmp_path, monkeypatch):
    base, resolver, server, _cfg = _dashboard(tmp_path, monkeypatch)
    try:
        resolver.upstream_mode = "udp"
        body = _get(f"{base}/")
        assert "Configuración" in body and "tab-config" in body
        assert "en uso" in body           # la tarjeta activa se marca
        assert "Cambiar a este modo" in body  # la otra ofrece el cambio
        assert "confirm(" in body             # con confirmacion previa
    finally:
        server.shutdown()
