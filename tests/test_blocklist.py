import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns.blocklist import Allowlist, Blocklist  # noqa: E402


def test_blocks_exact_domain(tmp_path):
    path = tmp_path / "blocklist.txt"
    path.write_text("malicious-example.com\n")
    blocklist = Blocklist(str(path))

    assert blocklist.is_blocked("malicious-example.com") is True


def test_blocks_subdomain(tmp_path):
    path = tmp_path / "blocklist.txt"
    path.write_text("malicious-example.com\n")
    blocklist = Blocklist(str(path))

    assert blocklist.is_blocked("sub.malicious-example.com") is True


def test_allows_clean_domain(tmp_path):
    path = tmp_path / "blocklist.txt"
    path.write_text("malicious-example.com\n")
    blocklist = Blocklist(str(path))

    assert blocklist.is_blocked("example.com") is False


def test_ignores_comments_and_blank_lines(tmp_path):
    path = tmp_path / "blocklist.txt"
    path.write_text("# comentario\n\nmalicious-example.com\n")
    blocklist = Blocklist(str(path))

    assert blocklist.is_blocked("malicious-example.com") is True


def test_combines_multiple_files(tmp_path):
    manual = tmp_path / "blocklist.txt"
    manual.write_text("manual-bad.com\n")
    feeds = tmp_path / "blocklist_feeds.txt"
    feeds.write_text("feed-bad.com\n")

    blocklist = Blocklist([str(manual), str(feeds)])

    assert blocklist.is_blocked("manual-bad.com") is True
    assert blocklist.is_blocked("feed-bad.com") is True
    assert blocklist.is_blocked("clean.com") is False


def test_reload_picks_up_new_entries(tmp_path):
    path = tmp_path / "blocklist.txt"
    path.write_text("old-bad.com\n")
    blocklist = Blocklist(str(path))
    assert blocklist.is_blocked("new-bad.com") is False

    path.write_text("old-bad.com\nnew-bad.com\n")
    blocklist.reload()

    assert blocklist.is_blocked("new-bad.com") is True


def test_allowlist_is_allowed_matches_domain_and_subdomain(tmp_path):
    path = tmp_path / "allowlist.txt"
    path.write_text("trusted-example.com\n")
    allowlist = Allowlist(str(path))

    assert allowlist.is_allowed("trusted-example.com") is True
    assert allowlist.is_allowed("sub.trusted-example.com") is True
    assert allowlist.is_allowed("other.com") is False


def test_allowlist_add_and_reload_persists_and_takes_effect_immediately(tmp_path):
    path = tmp_path / "allowlist.txt"
    allowlist = Allowlist(str(path))
    assert allowlist.is_allowed("new-domain.com") is False

    allowlist.add_and_reload("New-Domain.com")

    assert allowlist.is_allowed("new-domain.com") is True
    assert "new-domain.com" in path.read_text()


def test_blocklist_add_and_reload_takes_effect_immediately(tmp_path):
    path = tmp_path / "blocklist.txt"
    blocklist = Blocklist(str(path))
    assert blocklist.is_blocked("new-bad.com") is False

    blocklist.add_and_reload("New-Bad.com")

    assert blocklist.is_blocked("new-bad.com") is True
    assert "new-bad.com" in path.read_text()


def test_blocklist_remove_and_reload(tmp_path):
    path = tmp_path / "blocklist.txt"
    path.write_text("malicious-example.com\nkeep-me.com\n")
    blocklist = Blocklist(str(path))

    blocklist.remove_and_reload("malicious-example.com")

    assert blocklist.is_blocked("malicious-example.com") is False
    assert blocklist.is_blocked("keep-me.com") is True


def test_blocklist_remove_and_reload_only_touches_manual_file(tmp_path):
    manual_path = tmp_path / "blocklist.txt"
    manual_path.write_text("")
    feeds_path = tmp_path / "blocklist_feeds.txt"
    feeds_path.write_text("from-feed.com\n")
    blocklist = Blocklist([str(manual_path), str(feeds_path)])
    assert blocklist.is_blocked("from-feed.com") is True

    blocklist.remove_and_reload("from-feed.com")

    assert blocklist.is_blocked("from-feed.com") is True


def test_blocklist_manual_entries_lists_only_manual_domains(tmp_path):
    manual_path = tmp_path / "blocklist.txt"
    manual_path.write_text("# comentario\nmanual-bad.com\n\n")
    feeds_path = tmp_path / "blocklist_feeds.txt"
    feeds_path.write_text("feed-bad.com\n")
    blocklist = Blocklist([str(manual_path), str(feeds_path)])

    assert blocklist.manual_entries() == ["manual-bad.com"]
