import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns.logger_db import LoggerDB  # noqa: E402


def test_log_and_read_back(tmp_path):
    db = LoggerDB(str(tmp_path / "test.db"))

    db.log_query("127.0.0.1", "example.com", "A", False, source="upstream_primary")
    db.log_query(
        "127.0.0.1", "malicious-example.com", "A", True,
        reason="dominio en blocklist", source="blocklist",
    )
    db.log_query("127.0.0.1", "example.com", "A", False, source="cache")

    stats = db.stats()
    assert stats["total_queries"] == 3
    assert stats["blocked_queries"] == 1
    assert stats["cached_queries"] == 1

    blocked = db.recent_blocked(limit=5)
    assert len(blocked) == 1
    assert blocked[0][1] == "malicious-example.com"
