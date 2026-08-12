"""Publica en Pi-hole las listas de Secure-Intel.

    python scripts/publicar_en_pihole.py
    python scripts/publicar_en_pihole.py --probar     (no escribe nada)
    python scripts/publicar_en_pihole.py --forzar     (aunque no haya cambios)

Se corre a mano o desde un cron/systemd timer. No hace falta que el resolutor
esté prendido: esto no resuelve nada, solo le deja un archivo a Pi-hole y le
avisa.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns import publicador  # noqa: E402
from securedns.config_loader import load_config  # noqa: E402
from securedns.pihole_api import ClientePihole  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Publica las listas en Pi-hole")
    parser.add_argument("--probar", action="store_true",
                        help="dice qué haría, sin escribir ni tocar Pi-hole")
    parser.add_argument("--forzar", action="store_true",
                        help="publica y corre gravity aunque la lista no haya cambiado")
    args = parser.parse_args()

    cfg = load_config()
    if not cfg.pihole.habilitado:
        print("[SecureDNS] Pi-hole está desactivado en config.yaml "
              "(pihole.habilitado: false). No hago nada.")
        return 0

    if args.probar:
        dominios, origen = publicador.dominios_a_publicar(cfg)
        destino = Path(cfg.pihole.carpeta_listas) / cfg.pihole.nombre_lista
        print(f"[SecureDNS] {len(dominios)} dominios saldrían de {origen}")
        print(f"[SecureDNS] irían a {destino}")
        print(f"[SecureDNS] Pi-hole en {cfg.pihole.url}, gravity: "
              f"{'sí' if cfg.pihole.correr_gravity else 'no'}")
        return 0 if dominios else 1

    cliente = ClientePihole(cfg.pihole.url, cfg.pihole_password,
                            verificar_tls=cfg.pihole.verificar_tls)
    try:
        informe = publicador.publicar(cfg, cliente, forzar=args.forzar)
    finally:
        cliente.salir()

    print(f"[SecureDNS] {informe['detalle']}")
    for clave in ("lista", "gravity"):
        if informe.get(clave):
            print(f"[SecureDNS] {clave}: {informe[clave]}")
    return 0 if informe.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
