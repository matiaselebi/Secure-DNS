#!/usr/bin/env python3
"""Detiene el resolver DNS si está corriendo en segundo plano, usando el PID
guardado en data/dns.pid (ver run_dns.py)."""

import platform
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PID_FILE = PROJECT_ROOT / "data" / "dns.pid"


def main() -> None:
    if not PID_FILE.exists():
        print("[SecureDNS] No hay un archivo de PID: ¿está corriendo el resolver?")
        sys.exit(1)

    pid = int(PID_FILE.read_text().strip())

    if platform.system() == "Windows":
        result = subprocess.run(
            ["taskkill", "/PID", str(pid), "/F"], capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"[SecureDNS] No se pudo detener el proceso {pid}: {result.stderr.strip()}")
            sys.exit(1)
    else:
        import os
        import signal

        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            print(f"[SecureDNS] El proceso {pid} ya no existe.")
            PID_FILE.unlink(missing_ok=True)
            sys.exit(1)

    PID_FILE.unlink(missing_ok=True)
    print(f"[SecureDNS] Proceso {pid} detenido.")


if __name__ == "__main__":
    main()
