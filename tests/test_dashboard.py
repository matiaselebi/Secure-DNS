import sys
import threading
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns.blocklist import Allowlist, Blocklist  # noqa: E402
from securedns.dashboard import build_dashboard_server  # noqa: E402
from securedns.dns_server import ThreatIntelResolver  # noqa: E402
from securedns.logger_db import LoggerDB  # noqa: E402


def _make_dashboard_deps(tmp_path, logger_db):
    allowlist = Allowlist(str(tmp_path / "allowlist.txt"))
    blocklist = Blocklist(str(tmp_path / "blocklist.txt"))
    resolver = ThreatIntelResolver(
        blocklist=blocklist,
        logger_db=logger_db,
        upstream_primary="9.9.9.9",
        upstream_fallback="1.1.1.1",
        allowlist=allowlist,
    )
    return allowlist, blocklist, resolver


def test_dashboard_shows_stats(tmp_path):
    logger_db = LoggerDB(str(tmp_path / "logs.db"))
    logger_db.log_query("127.0.0.1", "malicious-example.com", "A", True, reason="dominio en blocklist")
    logger_db.log_query("127.0.0.1", "example.com", "A", False, source="upstream_primary")
    allowlist, blocklist, resolver = _make_dashboard_deps(tmp_path, logger_db)

    server = build_dashboard_server("127.0.0.1", 0, logger_db, allowlist, blocklist, resolver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)

    port = server.server_address[1]
    response = requests.get(f"http://127.0.0.1:{port}/", timeout=5)

    server.shutdown()

    assert response.status_code == 200
    assert "SecureDNS" in response.text
    assert "malicious-example.com" in response.text
    assert "Consultas totales" in response.text
    assert "Lista blanca" in response.text
    assert "Lista negra (manual)" in response.text
    assert "Borrar cache" in response.text


def test_allow_endpoint_adds_domain_and_redirects(tmp_path):
    logger_db = LoggerDB(str(tmp_path / "logs.db"))
    allowlist_path = tmp_path / "allowlist.txt"
    allowlist, blocklist, resolver = _make_dashboard_deps(tmp_path, logger_db)

    server = build_dashboard_server("127.0.0.1", 0, logger_db, allowlist, blocklist, resolver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)

    port = server.server_address[1]
    response = requests.get(
        f"http://127.0.0.1:{port}/allow?domain=trusted-example.com",
        timeout=5,
        allow_redirects=False,
    )

    server.shutdown()

    assert response.status_code == 303
    assert response.headers["Location"] == "/"
    assert allowlist.is_allowed("trusted-example.com") is True
    assert "trusted-example.com" in allowlist_path.read_text()


def test_unallow_endpoint_removes_domain(tmp_path):
    logger_db = LoggerDB(str(tmp_path / "logs.db"))
    allowlist, blocklist, resolver = _make_dashboard_deps(tmp_path, logger_db)
    allowlist.add_and_reload("trusted-example.com")

    server = build_dashboard_server("127.0.0.1", 0, logger_db, allowlist, blocklist, resolver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)

    port = server.server_address[1]
    response = requests.get(
        f"http://127.0.0.1:{port}/unallow?domain=trusted-example.com",
        timeout=5,
        allow_redirects=False,
    )

    server.shutdown()

    assert response.status_code == 303
    assert allowlist.is_allowed("trusted-example.com") is False


def test_blockdomain_and_unblockdomain_endpoints(tmp_path):
    logger_db = LoggerDB(str(tmp_path / "logs.db"))
    allowlist, blocklist, resolver = _make_dashboard_deps(tmp_path, logger_db)

    server = build_dashboard_server("127.0.0.1", 0, logger_db, allowlist, blocklist, resolver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    port = server.server_address[1]

    add_response = requests.get(
        f"http://127.0.0.1:{port}/blockdomain?domain=new-bad-example.com",
        timeout=5,
        allow_redirects=False,
    )
    assert add_response.status_code == 303
    assert blocklist.is_blocked("new-bad-example.com") is True

    remove_response = requests.get(
        f"http://127.0.0.1:{port}/unblockdomain?domain=new-bad-example.com",
        timeout=5,
        allow_redirects=False,
    )
    server.shutdown()
    assert remove_response.status_code == 303
    assert blocklist.is_blocked("new-bad-example.com") is False


def test_clear_cache_endpoint_empties_resolver_cache(tmp_path):
    logger_db = LoggerDB(str(tmp_path / "logs.db"))
    allowlist, blocklist, resolver = _make_dashboard_deps(tmp_path, logger_db)
    resolver._cache[("example.com", 1)] = (b"fake", 9999999999.0)
    assert resolver.cache_size() == 1

    server = build_dashboard_server("127.0.0.1", 0, logger_db, allowlist, blocklist, resolver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    port = server.server_address[1]

    response = requests.get(f"http://127.0.0.1:{port}/clear-cache", timeout=5, allow_redirects=False)

    server.shutdown()
    assert response.status_code == 303
    assert resolver.cache_size() == 0


def test_cache_count_endpoint_returns_plain_number(tmp_path):
    """Usado por la opción "Ver estado" del menú .bat para mostrar cuántas
    entradas tiene el cache sin tener que parsear el HTML del dashboard."""
    logger_db = LoggerDB(str(tmp_path / "logs.db"))
    allowlist, blocklist, resolver = _make_dashboard_deps(tmp_path, logger_db)
    resolver._cache[("a.com", 1)] = (b"x", 9999999999.0)
    resolver._cache[("b.com", 1)] = (b"y", 9999999999.0)

    server = build_dashboard_server("127.0.0.1", 0, logger_db, allowlist, blocklist, resolver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    port = server.server_address[1]

    response = requests.get(f"http://127.0.0.1:{port}/cache-count", timeout=5)

    server.shutdown()
    assert response.status_code == 200
    assert response.text.strip() == "2"


def test_blockdomain_endpoint_rejects_malformed_input(tmp_path):
    """Un valor pegado por error (URL completa, con espacios, etc.) no debe
    terminar escrito en el archivo de blocklist."""
    from urllib.parse import quote

    logger_db = LoggerDB(str(tmp_path / "logs.db"))
    allowlist, blocklist, resolver = _make_dashboard_deps(tmp_path, logger_db)

    server = build_dashboard_server("127.0.0.1", 0, logger_db, allowlist, blocklist, resolver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    port = server.server_address[1]

    response = requests.get(
        f"http://127.0.0.1:{port}/blockdomain?domain=" + quote("http://not-a-domain.com/x"),
        timeout=5,
        allow_redirects=False,
    )

    server.shutdown()
    assert response.status_code == 303
    assert blocklist.is_blocked("not-a-domain.com") is False
    assert "not-a-domain.com" not in blocklist.manual_entries()
