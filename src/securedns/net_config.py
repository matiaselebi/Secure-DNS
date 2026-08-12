"""Poner y sacar este resolver como DNS del sistema, sin dejarte sin internet.

EL BUG QUE ORIGINÓ LA ÚLTIMA VERSIÓN DE ESTE ARCHIVO

Reportado así: "dejé la suite prendida, reinicié la PC, y cuando quise buscar
en Google no cargaba".

El DNS de un adaptador de Windows **sobrevive al reinicio**: es una propiedad
de la placa de red, no del proceso. Entonces la secuencia era:

1. La suite prendida deja los adaptadores apuntando a 127.0.0.1.
2. Se reinicia la PC. Los adaptadores siguen apuntando a 127.0.0.1.
3. Windows levanta la red **mucho antes** que la tarea de inicio automático
   que arranca SecureDNS: el escritorio ya está y el resolver todavía no.
4. En esa ventana, y hasta que SecureDNS termine de arrancar, **ningún nombre
   resuelve**. Si por lo que sea el resolver no arranca (le falta el venv, el
   puerto 53 está tomado, el config quedó mal), no resuelve nunca más.

Ese agujero no se tapa arrancando más rápido: siempre va a haber un momento
entre que la red está lista y que el resolver escucha. Se tapa dejando un
**segundo servidor DNS** configurado detrás del nuestro.

POR QUÉ EL RESPALDO NO ROMPE EL FILTRADO

Windows consulta al primero y solo pasa al segundo si el primero **no
contesta**. Un dominio bloqueado no es "no contestar": SecureDNS responde
NXDOMAIN, que es una respuesta válida y definitiva, y ahí Windows no pregunta
a nadie más. O sea que el respaldo entra en juego exactamente en el único caso
que nos interesa: cuando SecureDNS no está.

La contra, que hay que decirla: mientras SecureDNS está caído, las consultas
salen sin filtrar por el respaldo. Es una decisión consciente de fallar
abierto, igual que el circuit breaker de SecureProxy con AbuseIPDB. Internet
sin filtro es molesto; sin internet es inusable, y lo primero que hace
cualquiera cuando "no anda nada" es desinstalar la herramienta. Se puede
apagar con `dns_del_sistema.respaldo: ""`.

EL SEGUNDO BUG: -ResetServerAddresses CON IP FIJA

Restaurar hacía `-ResetServerAddresses`, que quiere decir "pedile el DNS al
DHCP". En una máquina con **IP fija configurada a mano** no hay DHCP que
conteste, así que el adaptador se queda con CERO servidores DNS: apagar
SecureDNS te dejaba sin resolver nombres. Por eso ahora se **guarda** lo que
había antes de tocar nada y se repone eso mismo, y `-ResetServerAddresses`
queda solo como último recurso cuando no hay nada guardado.

QUÉ MÁS HACE ESTE MÓDULO

Apagar SecureDNS también tenía una consecuencia que no era obvia y que dejaba la
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
from pathlib import Path

# Dónde se anota qué DNS tenía cada adaptador antes de que lo tocáramos. Va a
# un archivo y no a memoria porque el proceso que pone el DNS puede no ser el
# mismo que lo saca: lo pone el .bat o SecureCenter, y lo saca stop_dns.py,
# el botón del panel o un Ctrl+C.
ARCHIVO_PREVIO = Path(__file__).resolve().parent.parent.parent / "data" / "dns_previo.json"

# El DNS de respaldo que queda DETRÁS del nuestro. Ver el docstring: tapa la
# ventana entre que Windows levanta la red y que SecureDNS empieza a escuchar,
# que es de varios segundos en cada reinicio.
#
# Quad9 y no un DNS cualquiera: es el mismo al que SecureDNS reenvía por
# DNS-over-TLS, así que durante esa ventana las consultas van al mismo lugar
# al que hubieran ido igual (aunque sin cifrar y sin nuestro filtro).
RESPALDO_POR_DEFECTO = "9.9.9.9"

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


def dns_actuales() -> dict[int, list[str]]:
    """Qué servidores DNS tiene hoy cada adaptador activo. {indice: [ips]}."""
    if not es_windows():
        return {}
    comando = (
        "@(Get-DnsClientServerAddress -AddressFamily IPv4 | "
        "Select-Object InterfaceIndex, ServerAddresses) | ConvertTo-Json -Compress"
    )
    ok, salida = _powershell(comando)
    if not ok or not salida:
        return {}
    try:
        datos = json.loads(salida)
    except json.JSONDecodeError:
        return {}
    if isinstance(datos, dict):
        datos = [datos]
    salida_final: dict[int, list[str]] = {}
    for fila in datos:
        try:
            indice = int(fila["InterfaceIndex"])
        except (KeyError, TypeError, ValueError):
            continue
        servidores = fila.get("ServerAddresses") or []
        if isinstance(servidores, str):
            servidores = [servidores]
        salida_final[indice] = [str(s) for s in servidores]
    return salida_final


def guardar_previos(actuales: dict[int, list[str]] | None = None) -> dict:
    """Anota qué DNS tenía cada adaptador ANTES de que lo apuntáramos acá.

    Solo se guarda lo que no somos nosotros: si esto corre dos veces seguidas
    (prender el núcleo estando ya prendido, por ejemplo), la segunda no puede
    pisar el original con un `127.0.0.1` y hacer que restaurar sea un no-op.
    """
    actuales = dns_actuales() if actuales is None else actuales
    limpios = {
        str(indice): [s for s in servidores if s not in NUESTRAS]
        for indice, servidores in actuales.items()
    }
    limpios = {k: v for k, v in limpios.items() if v}
    if not limpios:
        return {}
    try:
        ARCHIVO_PREVIO.parent.mkdir(parents=True, exist_ok=True)
        anterior = leer_previos()
        # Se fusiona con lo que ya había: un adaptador que hoy no tiene DNS
        # propio no puede borrar el que anotamos la vez pasada.
        anterior.update(limpios)
        ARCHIVO_PREVIO.write_text(json.dumps(anterior, indent=2), encoding="utf-8")
        return anterior
    except OSError:
        return {}


def leer_previos() -> dict:
    try:
        return json.loads(ARCHIVO_PREVIO.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def poner_nuestro_dns(respaldo: str = RESPALDO_POR_DEFECTO) -> dict:
    """Apunta los adaptadores activos a nosotros, con un respaldo detrás.

    Antes de tocar nada guarda lo que había. El respaldo va SEGUNDO: Windows
    pregunta al primero y solo pasa al segundo si el primero no contesta.
    """
    resultado = {"adaptadores": [], "error": None, "respaldo": respaldo}
    if not es_windows():
        return resultado
    guardar_previos()
    direcciones = "'127.0.0.1'" + (f",'{respaldo}'" if respaldo else "")
    ok, salida = _powershell(
        "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object "
        "{ Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex "
        f"-ServerAddresses {direcciones} -ErrorAction Stop }}"
    )
    if not ok:
        resultado["error"] = salida or "no pude cambiar el DNS de los adaptadores"
        return resultado
    _powershell("Clear-DnsClientCache")
    resultado["adaptadores"] = [a["nombre"] for a in adaptadores_apuntando_a_nosotros()]
    return resultado


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

    # Se repone LO QUE HABÍA, no "automático". `-ResetServerAddresses`
    # significa "pedile el DNS al DHCP", y en una máquina con IP fija puesta a
    # mano no hay DHCP que conteste: el adaptador queda con cero servidores y
    # apagar SecureDNS te deja sin resolver nombres. Solo se usa como último
    # recurso, cuando no tenemos nada anotado de ese adaptador.
    previos = leer_previos()
    partes = []
    for adaptador in adaptadores:
        guardados = previos.get(str(adaptador["indice"]))
        if guardados:
            lista = ",".join(f"'{s}'" for s in guardados)
            partes.append(f"Set-DnsClientServerAddress -InterfaceIndex "
                          f"{adaptador['indice']} -ServerAddresses {lista} "
                          f"-ErrorAction Stop")
        else:
            partes.append(f"Set-DnsClientServerAddress -InterfaceIndex "
                          f"{adaptador['indice']} -ResetServerAddresses "
                          f"-ErrorAction Stop")
    ok, salida = _powershell("; ".join(partes))
    if not ok:
        # El motivo casi siempre es el mismo: cambiar el DNS de una placa pide
        # permisos de administrador. Se dice así, con el comando a mano, en vez
        # de un "falló" pelado: quien lee esto está justo sin internet.
        resultado["error"] = salida or "no se pudo cambiar el DNS de los adaptadores"
        return resultado

    resultado["restaurados"] = [a["nombre"] for a in adaptadores]
    resultado["desde_lo_guardado"] = bool(previos)
    _powershell("Clear-DnsClientCache")
    # Verificación honesta: si después de restaurar la máquina igual no
    # resuelve, es mejor dejarle un DNS público que dejarla "prolija" y sin
    # internet. Es el mismo criterio que el respaldo de arriba.
    if not _resuelve_algo():
        indices = ",".join(str(a["indice"]) for a in adaptadores)
        _powershell(
            f"{indices} | ForEach-Object {{ Set-DnsClientServerAddress "
            f"-InterfaceIndex $_ -ServerAddresses '{RESPALDO_POR_DEFECTO}' "
            f"-ErrorAction SilentlyContinue }}")
        resultado["rescate"] = RESPALDO_POR_DEFECTO
    return resultado


def _resuelve_algo(nombre: str = "one.one.one.one") -> bool:
    """¿La máquina puede resolver un nombre ahora mismo?

    Se usa después de restaurar para no dejarla sin DNS en silencio. Un nombre
    que no es de ningún servicio nuestro, para que la respuesta hable de la
    resolución y no de si nuestra herramienta está arriba.
    """
    import socket

    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(nombre)
        return True
    except (OSError, socket.gaierror):
        return False


def _modo_dice_que_toquemos_el_dns() -> bool:
    """¿El config dice que el DNS del sistema lo maneja SecureDNS?

    Se lee el config acá adentro, aunque el resto del módulo no lo necesite,
    porque estas dos funciones las llama SecureCenter por su cuenta (mandando
    un `import` a un subproceso) y no tiene forma de pasarnos el config ya
    cargado. Si el chequeo viviera del lado de SecureCenter, el conocimiento
    del DNS del sistema volvería a estar en dos lugares, que es exactamente lo
    que causó el apagón del reinicio.
    """
    try:
        from .config_loader import load_config
        from .modo import toca_el_dns_del_sistema

        return toca_el_dns_del_sistema(load_config())
    except Exception as exc:  # noqa: BLE001
        # Si no se puede saber, se asume que sí: es el comportamiento de
        # siempre. Equivocarse para este lado es recuperable; para el otro,
        # deja la máquina sin resolver nombres.
        print(f"[SecureDNS] no pude leer el modo ({exc}); asumo resolutor propio")
        return True


def tomar_el_dns_si_corresponde(respaldo: str = RESPALDO_POR_DEFECTO) -> dict:
    """Pone 127.0.0.1 en el adaptador, pero SOLO si acá resuelve SecureDNS.

    Es la puerta que usa SecureCenter al encender el núcleo. Sin esta
    comprobación, encender la suite con SecureDNS en modo Pi-hole apuntaría la
    máquina a un 127.0.0.1 donde no escucha nadie: internet cortado y ni un
    mensaje de error. Es el mismo apagón que ya pasó una vez por otro motivo,
    y por eso la decisión vive en un solo lugar.
    """
    if not _modo_dice_que_toquemos_el_dns():
        aviso = ("resuelve Pi-hole: el DNS del sistema no se toca "
                 "(tiene que apuntar a Pi-hole, no a 127.0.0.1)")
        print(f"[SecureDNS] {aviso}")
        return {"aplicados": [], "error": "", "salteado": True, "motivo": aviso}
    return poner_nuestro_dns(respaldo)


def devolver_el_dns_si_corresponde(prefijo: str = "[SecureDNS]") -> dict:
    """La otra mitad: no se restaura lo que nunca se tocó.

    Hoy restaurar igual no rompería nada, pero pondría a SecureDNS a manotear
    los adaptadores de una máquina donde el DNS lo administra otro, que es
    justo lo que la jubilación del resolutor viene a terminar.
    """
    if not _modo_dice_que_toquemos_el_dns():
        return {"restaurados": [], "error": "", "salteado": True}
    return restaurar_e_informar(prefijo)


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
