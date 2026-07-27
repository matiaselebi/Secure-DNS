import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns.validation import is_valid_domain  # noqa: E402


def test_accepts_plain_domains():
    assert is_valid_domain("example.com") is True
    assert is_valid_domain("sub.example.com") is True
    assert is_valid_domain("EXAMPLE.COM") is True
    assert is_valid_domain("  example.com  ") is True


def test_rejects_empty_and_whitespace():
    assert is_valid_domain("") is False
    assert is_valid_domain("   ") is False
    assert is_valid_domain("example .com") is False


def test_rejects_urls_and_paths():
    assert is_valid_domain("http://example.com") is False
    assert is_valid_domain("https://example.com/path") is False
    assert is_valid_domain("example.com/path") is False
    assert is_valid_domain("example.com:8080") is False


def test_accepts_ip_literals():
    """El proxy también puede filtrar por IP directa (ej. tests que usan
    127.0.0.1 como "dominio" bloqueado), no solo por nombre."""
    assert is_valid_domain("127.0.0.1") is True
    assert is_valid_domain("8.8.8.8") is True
    assert is_valid_domain("::1") is True


def test_rejects_malformed_domains():
    assert is_valid_domain("-example.com") is False
    assert is_valid_domain("example-.com") is False
    assert is_valid_domain("example") is False
    assert is_valid_domain("...") is False
    assert is_valid_domain("example..com") is False
