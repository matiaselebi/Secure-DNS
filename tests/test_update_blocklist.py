import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import update_blocklist  # noqa: E402


class FakeResponse:
    def __init__(self, text: str):
        self.text = text

    def raise_for_status(self):
        pass


def test_fetch_urlhaus_domains_parses_hostfile(monkeypatch):
    fake_text = "\n".join(
        ["# comentario", "0.0.0.0 malicious-domain-1.com", "0.0.0.0 malicious-domain-2.com", ""]
    )
    monkeypatch.setattr(update_blocklist.requests, "get", lambda *a, **k: FakeResponse(fake_text))

    domains = update_blocklist.fetch_urlhaus_domains()

    assert domains == {"malicious-domain-1.com", "malicious-domain-2.com"}


def test_fetch_openphish_domains_extracts_hostname(monkeypatch):
    fake_text = "\n".join(
        ["http://phishing-site.example/login/paypal", "https://another-phish.example/wp-admin", ""]
    )
    monkeypatch.setattr(update_blocklist.requests, "get", lambda *a, **k: FakeResponse(fake_text))

    domains = update_blocklist.fetch_openphish_domains()

    assert domains == {"phishing-site.example", "another-phish.example"}


def test_is_stale_when_file_missing(tmp_path):
    assert update_blocklist.is_stale(tmp_path / "no-existe.txt", min_interval_hours=6) is True


def test_is_stale_respects_interval(tmp_path):
    path = tmp_path / "blocklist_feeds.txt"
    path.write_text("example.com\n")

    assert update_blocklist.is_stale(path, min_interval_hours=6) is False

    ten_hours_ago = time.time() - (10 * 3600)
    os.utime(path, (ten_hours_ago, ten_hours_ago))

    assert update_blocklist.is_stale(path, min_interval_hours=6) is True


def test_fetch_ad_tracker_domains_parses_hosts_format(monkeypatch):
    fake_text = "\n".join(
        [
            "# comentario",
            "0.0.0.0 localhost",
            "0.0.0.0 ads.example.com",
            "127.0.0.1 tracker.example.net",
            "",
        ]
    )
    monkeypatch.setattr(update_blocklist.requests, "get", lambda *a, **k: FakeResponse(fake_text))

    domains = update_blocklist.fetch_ad_tracker_domains()

    assert domains == {"ads.example.com", "tracker.example.net"}
    assert "localhost" not in domains


def test_main_skips_ad_tracker_download_when_not_included(monkeypatch, tmp_path):
    monkeypatch.setattr(update_blocklist, "OUTPUT_PATH", tmp_path / "feeds.txt")
    monkeypatch.setattr(update_blocklist, "AD_TRACKER_OUTPUT_PATH", tmp_path / "adtracker.txt")
    monkeypatch.setattr(update_blocklist, "fetch_urlhaus_domains", lambda: {"bad.example"})
    monkeypatch.setattr(update_blocklist, "fetch_openphish_domains", lambda: set())

    def fail_if_called():
        raise AssertionError("no debería descargar el feed de ads/trackers")

    monkeypatch.setattr(update_blocklist, "fetch_ad_tracker_domains", fail_if_called)

    updated = update_blocklist.main(force=True, include_ad_tracker=False)

    assert updated is True
    assert not (tmp_path / "adtracker.txt").exists()


def test_main_downloads_ad_tracker_when_included(monkeypatch, tmp_path):
    monkeypatch.setattr(update_blocklist, "OUTPUT_PATH", tmp_path / "feeds.txt")
    monkeypatch.setattr(update_blocklist, "AD_TRACKER_OUTPUT_PATH", tmp_path / "adtracker.txt")
    monkeypatch.setattr(update_blocklist, "fetch_urlhaus_domains", lambda: set())
    monkeypatch.setattr(update_blocklist, "fetch_openphish_domains", lambda: set())
    monkeypatch.setattr(update_blocklist, "fetch_ad_tracker_domains", lambda: {"ads.example.com"})

    updated = update_blocklist.main(force=True, include_ad_tracker=True)

    assert updated is True
    assert "ads.example.com" in (tmp_path / "adtracker.txt").read_text()
