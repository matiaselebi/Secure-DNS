"""Trae las consultas de Pi-hole a la base de SecureDNS y las analiza acá.

    python scripts/importar_de_pihole.py
    python scripts/importar_de_pihole.py --repetir    (se queda importando)

Después de importar, la pestaña Detección del panel de SecureDNS ya está
mirando el tráfico de TODA la casa: cada equipo con su IP, que es lo que la
detección de túneles necesita para agrupar por (equipo, dominio padre).

Se puede correr a mano, desde un cron, o dejarlo con --repetir bajo systemd.
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns import pihole_consultas  # noqa: E402
from securedns.blocklist import Blocklist  # noqa: E402
from securedns.config_loader import load_config  # noqa: E402
from securedns.logger_db import LoggerDB  # noqa: E402
from securedns.view_prefs import ViewPrefs  # noqa: E402


def _herramientas(cfg):
    """La blocklist y las preferencias de ruido, para enriquecer lo importado.

    Son de otra capa que el logger, así que se arman acá y se pasan. La
    categoría es lo que convierte la importación en algo nuestro: Pi-hole sabe
    que bloqueó, pero no si fue malware, phishing o publicidad, porque gravity
    mezcla todas las listas en una sola bolsa.
    """
    rutas = [str(cfg.resolve_path(cfg.filtering.blocklist_path)),
             str(cfg.resolve_path(cfg.filtering.feeds_blocklist_path))]
    if cfg.filtering.enable_ad_tracker_blocklist:
        rutas.append(str(cfg.resolve_path(cfg.filtering.ad_tracker_blocklist_path)))
    listas = Blocklist(rutas)

    def categoria_de(dominio: str) -> str:
        return listas.categoria_de(dominio) if listas.is_blocked(dominio) else ""

    try:
        prefs = ViewPrefs()
        es_ruido = prefs.es_ruidoso
    except Exception:  # noqa: BLE001 - sin preferencias se importa igual
        es_ruido = None
    return categoria_de, es_ruido


def una_vuelta(cfg, logger, categoria_de, es_ruido) -> int:
    informe = pihole_consultas.importar(
        cfg, logger, categoria_de=categoria_de, es_ruido=es_ruido)
    print(f"[SecureDNS] {informe['detalle']}")
    return 0 if informe.get("ok") else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Importa las consultas de Pi-hole")
    parser.add_argument("--repetir", action="store_true",
                        help="se queda importando cada tanto en vez de una sola vez")
    args = parser.parse_args()

    cfg = load_config()
    if not cfg.pihole.habilitado or not cfg.pihole.importar_consultas:
        print("[SecureDNS] la importación desde Pi-hole está apagada en el "
              "config.yaml (pihole.habilitado / pihole.importar_consultas)")
        return 0

    logger = LoggerDB(str(cfg.resolve_path(cfg.logging.db_path)), cfg.logging.max_rows)
    categoria_de, es_ruido = _herramientas(cfg)

    if not args.repetir:
        return una_vuelta(cfg, logger, categoria_de, es_ruido)

    espera = max(60.0, float(cfg.pihole.minutos_entre_importaciones) * 60.0)
    print(f"[SecureDNS] importando de Pi-hole cada "
          f"{cfg.pihole.minutos_entre_importaciones} minutos. Ctrl+C para cortar.")
    while True:
        try:
            una_vuelta(cfg, logger, categoria_de, es_ruido)
        except KeyboardInterrupt:
            print("[SecureDNS] corto.")
            return 0
        except Exception as exc:  # noqa: BLE001
            # Un error en una vuelta no puede matar el bucle: la próxima
            # importación arranca desde la misma marca y no se pierde nada.
            print(f"[SecureDNS] la importación falló esta vuelta: {exc}")
        try:
            time.sleep(espera)
        except KeyboardInterrupt:
            print("[SecureDNS] corto.")
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
