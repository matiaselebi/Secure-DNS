"""Aislamiento del árbol del proyecto durante los tests.

Motivo real: `/nivel?v=paranoico` y `/config?k=...` escriben el config con
`config_writer`, y la ruta la sacan de `config_loader.PROJECT_ROOT`. Los tests
del panel levantaban un dashboard de verdad contra un tmp_path, pero
PROJECT_ROOT seguía apuntando al repo, así que esas escrituras caían sobre
`config/config.yaml` de verdad. Correr la suite dejaba el archivo que se
entrega con `upstream_mode: udp` y el fallback apagado, y eso se subía sin que
nadie lo notara: ningún test miraba el archivo del repo.

La solución no es arreglar ese test y seguir: es que NINGÚN test pueda escribir
ahí, ni los que se escriban el año que viene. Se arma un árbol paralelo con
todo enlazado al repo menos `config/`, que se copia de verdad. Lo que lee sigue
leyendo lo mismo; lo que escribe el config escribe en la copia y se descarta.
"""

import shutil
import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))


@pytest.fixture(autouse=True)
def _proyecto_aislado(tmp_path_factory, monkeypatch):
    espejo = tmp_path_factory.mktemp("proyecto")
    for entrada in RAIZ.iterdir():
        if entrada.name in {"config", ".git", "__pycache__", ".pytest_cache"}:
            continue
        (espejo / entrada.name).symlink_to(entrada, entrada.is_dir())
    shutil.copytree(RAIZ / "config", espejo / "config")

    import securedns.config_loader as cl

    monkeypatch.setattr(cl, "PROJECT_ROOT", espejo)
    yield espejo
