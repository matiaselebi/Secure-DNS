#!/usr/bin/env python3
"""Detiene el resolver DNS y devuelve el DNS del sistema a automático.

Las dos cosas, y en ese orden, porque hacer solo la primera es el bug que
dejaba la máquina sin internet: `SecureDNS.bat` pone 127.0.0.1 como servidor
DNS de los adaptadores, y este script -que es el que llama SecureCenter-
mataba el proceso sin restaurarlos. A partir de ahí ningún nombre resolvía y
parecía que se había caído el wifi.

El resolver también restaura al cerrarse por su cuenta (ver run_dns.py), así
que en el camino normal esto no encuentra nada que hacer. Se deja igual
porque acá se lo mata a la fuerza: si el proceso está colgado y no llega a
correr su propio cierre, este script es lo único que queda para arreglarlo.
"""

import platform
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

PID_FILE = PROJECT_ROOT / "data" / "dns.pid"

from securedns import net_config  # noqa: E402


def _matar(pid: int) -> bool:
    if platform.system() == "Windows":
        resultado = subprocess.run(
            ["taskkill", "/PID", str(pid), "/F"], capture_output=True, text=True
        )
        if resultado.returncode != 0:
            print(f"[SecureDNS] No se pudo detener el proceso {pid}: {resultado.stderr.strip()}")
            return False
        return True

    import os
    import signal

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        print(f"[SecureDNS] El proceso {pid} ya no existe.")
        return False
    return True


def main() -> None:
    detenido = False
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
        except ValueError:
            print("[SecureDNS] El archivo de PID está ilegible; lo borro.")
            pid = 0
        PID_FILE.unlink(missing_ok=True)
        if pid:
            detenido = _matar(pid)
            if detenido:
                print(f"[SecureDNS] Proceso {pid} detenido.")
    else:
        print("[SecureDNS] No hay un archivo de PID: ¿está corriendo el resolver?")

    # Esto va SIEMPRE, haya habido proceso que matar o no. El caso peor es
    # justamente cuando no lo hay: el resolver ya se murió (se colgó, lo mató
    # Windows, se cerró la sesión) y los adaptadores quedaron apuntando a un
    # 127.0.0.1 vacío. Ahí es cuando más falta hace.
    #
    # La variante "_si_corresponde" mira el modo antes: si acá resuelve
    # Pi-hole, SecureDNS nunca tocó el adaptador y no tiene por qué tocarlo
    # ahora. Restaurarlo igual sería manotear la red de una máquina donde el
    # DNS lo administra otro.
    resultado = net_config.devolver_el_dns_si_corresponde()

    if not detenido and not resultado.get("hacia_falta"):
        sys.exit(1)


if __name__ == "__main__":
    main()
