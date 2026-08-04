"""Dejar el DNS del sistema como estaba cuando el resolver se apaga.

POR QUÉ EXISTE ESTE ARCHIVO

Apagar SecureDNS tenía una consecuencia que no era obvia y que dejaba la
máquina sin internet: `SecureDNS.bat` pone `127.0.0.1` como servidor DNS de
todos los adaptadores activos, pero apagar el resolver desde cualquier lado
que no fuera la opción 2 de ese mismo `.bat` -desde SecureCenter, desde
`scripts/stop_dns.py`, con Ctrl+C, o cerrando la sesión- mataba el proceso y
dejaba los adaptadores apuntando a un `127.0.0.1` donde ya no escuchaba
nadie. Resultado: ningún nombre resuelve, y parece que se cayó el wifi.

Se notaba así: había que abrir PowerShell y correr a mano

    Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {
      Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses }
    ipconfig /flushdns

Eso funciona pero es más bruto de lo necesario: resetea TODOS los adaptadores
activos, incluidos los que nunca tuvieron nada que ver con SecureDNS. Si en
el trabajo tenés un DNS interno puesto a mano en la placa de red, ese comando
te lo borra también.

QUÉ HACE ESTE MÓDULO

Lo mismo, pero preciso: toca únicamente los adaptadores que están apuntando a
127.0.0.1 o a ::1, o sea los que apuntan a nosotros. Un adaptador con
cualquier otro DNS configurado se queda como está, porque no lo pusimos
nosotros.

Vive en un módulo aparte y no adentro de un script para que TODOS los caminos
de apagado usen exactamente el mismo código: `stop_dns.py`, el botón del
panel, Ctrl+C y el `.bat`. El bug original fue justamente que había dos
caminos y solo uno restauraba.

En Linux/macOS no hace nada: ahí el DNS se configura de otra forma (systemd
-resolved, NetworkManager, /etc/resolv.conf) y no es este script el que lo
cambia, así que tampoco le corresponde deshacerlo.
"""

import json
import platform
import shutil
import subprocess

# Las direcciones que significan "el resolver de esta misma máquina". Si un
# adaptador apunta a una de estas, lo pusimos nosotros.
NUESTRAS = ("127.0.0.1", "::1")

# Techo de espera de cada comando de PowerShell. Arrancar powershell.exe es
# lento pero no tanto; si tarda más que esto, algo está trabado y es mejor
# avisar que colgar el apagado del resolver para siempre.
TIMEOUT = 25

COMANDO_MANUAL = (
    "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object "
    "{ Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex "
    "-ResetServerAddresses }; ipconfig /flushdns"
)


def es_windows() -> bool:
    return platform.system() == "Windows"


def _powershell(comando: str) -> tuple[bool, str]:
    """Corre un comando de PowerShell. Devuelve (salió bien, salida/error)."""
    ejecutable = shutil.which("powershell") or shutil.which("pwsh")
    if ejecutable is None:
        return False, "no encontré powershell en el sistema"
    try:
        resultado = subprocess.run(
            [ejecutable, "-NoProfile", "-NonInteractive", "-Command", comando],
            capture_output=True, text=True, timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False, "PowerShell no respondió a tiempo"
    except OSError as exc:
        return False, str(exc)
    if resultado.returncode != 0:
        return False, (resultado.stderr or resultado.stdout).strip()
    return True, resultado.stdout.strip()


def adaptadores_apuntando_a_nosotros() -> list[dict]:
    """Los adaptadores cuyo DNS somos nosotros. Lista de {indice, nombre}.

    Se pregunta en vez de suponer. El `.bat` configura "todos los adaptadores
    activos", pero entre que los configuró y que se apaga el resolver puede
    haber cambiado cualquier cosa: una placa que se desconectó, una VPN que
    apareció, otro programa que tocó el DNS. Lo único confiable es mirar cómo
    está el sistema AHORA.
    """
    if not es_windows():
        return []
    filtro = " -or ".join(f"$_.ServerAddresses -contains '{ip}'" for ip in NUESTRAS)
    # El @() de afuera fuerza un array aunque haya un solo adaptador: sin eso
    # ConvertTo-Json devuelve un objeto suelto y el parseo se rompe justo en
    # el caso más común, que es tener una sola placa de red.
    comando = (
        "@(Get-DnsClientServerAddress | Where-Object { " + filtro + " } | "
        "Select-Object InterfaceIndex, InterfaceAlias) | ConvertTo-Json -Compress"
    )
    ok, salida = _powershell(comando)
    if not ok or not salida:
        return []
    try:
        datos = json.loads(salida)
    except json.JSONDecodeError:
        return []
    if isinstance(datos, dict):
        datos = [datos]

    # Un mismo adaptador aparece dos veces si tiene IPv4 e IPv6 apuntando acá.
    vistos: dict[int, str] = {}
    for fila in datos:
        try:
            indice = int(fila["InterfaceIndex"])
        except (KeyError, TypeError, ValueError):
            continue
        vistos.setdefault(indice, str(fila.get("InterfaceAlias") or f"adaptador {indice}"))
    return [{"indice": i, "nombre": n} for i, n in sorted(vistos.items())]


def restaurar_dns_automatico() -> dict:
    """Devuelve a DHCP los adaptadores que apuntan a este resolver.

    Devuelve un diccionario con `restaurados` (nombres), `error` (texto o
    None) y `hacia_falta` (si había algo que restaurar). No lanza excepciones:
    esto corre en el camino de apagado, y que falle no puede impedir que el
    proceso termine.
    """
    resultado = {"restaurados": [], "error": None, "hacia_falta": False}
    if not es_windows():
        return resultado

    adaptadores = adaptadores_apuntando_a_nosotros()
    if not adaptadores:
        return resultado
    resultado["hacia_falta"] = True

    indices = ",".join(str(a["indice"]) for a in adaptadores)
    ok, salida = _powershell(
        f"{indices} | ForEach-Object {{ Set-DnsClientServerAddress "
        "-InterfaceIndex $_ -ResetServerAddresses -ErrorAction Stop }"
    )
    if not ok:
        # El motivo casi siempre es el mismo: cambiar el DNS de una placa pide
        # permisos de administrador. Se dice así, con el comando a mano, en vez
        # de un "falló" pelado: quien lee esto está justo sin internet.
        resultado["error"] = salida or "no se pudo cambiar el DNS de los adaptadores"
        return resultado

    resultado["restaurados"] = [a["nombre"] for a in adaptadores]
    _powershell("Clear-DnsClientCache")
    return resultado


def restaurar_e_informar(prefijo: str = "[SecureDNS]") -> dict:
    """Restaura e imprime qué pasó, con el comando manual si falló."""
    resultado = restaurar_dns_automatico()
    if not es_windows():
        return resultado
    if resultado["restaurados"]:
        nombres = ", ".join(resultado["restaurados"])
        print(f"{prefijo} DNS devuelto a automático en: {nombres} (y cache vaciado)")
    elif resultado["error"]:
        print(f"{prefijo} NO pude devolver el DNS a automático: {resultado['error']}")
        print(f"{prefijo} Tu PC quedó apuntando a 127.0.0.1, donde ya no hay nadie:")
        print(f"{prefijo} hasta que lo arregles no vas a poder resolver nombres.")
        print(f"{prefijo} Abrí PowerShell COMO ADMINISTRADOR y pegá esto:")
        print()
        print(f"    {COMANDO_MANUAL}")
        print()
    return resultado
