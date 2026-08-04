"""El config que se sube tiene que ser el que dice el README.

Esto no prueba código: prueba el archivo que se entrega. Ya pasó dos veces que
`config/config.yaml` quedara con los valores que había usado para probar (el
puerto 15353 del resolver, el 18890 del panel, la lista de ads prendida), y
alguien que clona el repo se lleva ESO, no lo que documenta el README. Es un
error invisible para el resto de la suite de tests, porque todos los demás
arman su propia configuración en un tmp_path.
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

RAIZ = Path(__file__).resolve().parent.parent

# Clave (con puntos) -> valor que el README promete como default.
DEFAULTS = {
    "dns.host": "127.0.0.1",
    "dns.port": 53,
    "dns.upstream_primary": "9.9.9.9",
    "dns.upstream_fallback": "1.1.1.1",
    "dns.upstream_mode": "dot",
    "dns.dot_fallback_to_udp": True,
    "filtering.enable_ad_tracker_blocklist": False,
    "filtering.block_mode": "nxdomain",
    "filtering.feeds_update_interval_hours": 6,
    "logging.max_rows": 200000,
    "dashboard.host": "127.0.0.1",
    "dashboard.port": 8890,
    "dashboard.hide_noise": True,
    "intel.rdap_enabled": False,
    "intel.alerts_enabled": True,
    "intel.telegram_enabled": False,
}


@pytest.fixture(scope="module")
def config():
    with open(RAIZ / "config" / "config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


@pytest.mark.parametrize("clave,esperado", sorted(DEFAULTS.items()))
def test_el_valor_es_el_documentado(config, clave, esperado):
    seccion, campo = clave.split(".")
    actual = config[seccion][campo]
    assert actual == esperado, (
        f"config/config.yaml tiene {clave}={actual!r} pero el README dice "
        f"{esperado!r}. Si el default cambió a propósito, actualizá el README "
        f"y esta lista; si no, quedó un valor de prueba."
    )


def test_no_quedaron_secretos_en_el_config(config):
    """El token de Telegram y el chat van en .env, nunca acá."""
    texto = (RAIZ / "config" / "config.yaml").read_text(encoding="utf-8")
    for sospechoso in ("token", "chat_id", "api_key", "password"):
        for linea in texto.splitlines():
            limpia = linea.split("#")[0]
            assert sospechoso not in limpia.lower(), f"posible secreto: {linea}"
