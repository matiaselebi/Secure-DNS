"""Que apagar el resolver no te deje sin resolver nombres.

Este archivo entero existe por un bug que se sufrió de verdad: apagar
SecureDNS desde SecureCenter mataba el proceso pero dejaba a Windows
apuntando a un 127.0.0.1 donde ya no escuchaba nadie, así que la máquina no
resolvía ningún nombre y parecía que se había caído el wifi. Había que abrir
PowerShell y resetear los adaptadores a mano, cada vez.

El reset del DNS estaba escrito en el `.bat` y el matar el proceso en
`stop_dns.py`: dos caminos, y solo uno restauraba. Los tests de acá fijan que
haya UN solo lugar que restaura y que todos los caminos pasen por él.

Los comandos de PowerShell se simulan: la lógica que importa -a qué
adaptadores tocar y a cuáles no- es Python, y probarla no necesita Windows.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns import net_config  # noqa: E402


class _PowerShellFalso:
    """Reemplaza a `_powershell`. Guarda qué se le pidió y contesta lo que se
    le haya cargado."""

    def __init__(self, adaptadores_json: str = "[]", falla_el_set: str = ""):
        self.adaptadores_json = adaptadores_json
        self.falla_el_set = falla_el_set
        self.comandos: list[str] = []

    def __call__(self, comando: str) -> tuple[bool, str]:
        self.comandos.append(comando)
        if "Get-DnsClientServerAddress" in comando:
            return True, self.adaptadores_json
        if "Set-DnsClientServerAddress" in comando and self.falla_el_set:
            return False, self.falla_el_set
        return True, ""


@pytest.fixture()
def en_windows(monkeypatch):
    """El módulo no hace nada fuera de Windows, así que para probar la lógica
    hay que decirle que sí lo está."""
    monkeypatch.setattr(net_config, "es_windows", lambda: True)


def _instalar(monkeypatch, falso):
    monkeypatch.setattr(net_config, "_powershell", falso)
    return falso


UN_ADAPTADOR = '[{"InterfaceIndex":12,"InterfaceAlias":"Wi-Fi"}]'
# Windows PowerShell 5.1 serializa un objeto solo como objeto, no como lista.
UN_ADAPTADOR_SIN_ARRAY = '{"InterfaceIndex":12,"InterfaceAlias":"Wi-Fi"}'
DOS_ADAPTADORES = (
    '[{"InterfaceIndex":12,"InterfaceAlias":"Wi-Fi"},'
    ' {"InterfaceIndex":5,"InterfaceAlias":"Ethernet"}]'
)
# El mismo adaptador aparece dos veces si tiene IPv4 e IPv6 apuntando acá.
DUPLICADO = (
    '[{"InterfaceIndex":12,"InterfaceAlias":"Wi-Fi"},'
    ' {"InterfaceIndex":12,"InterfaceAlias":"Wi-Fi"}]'
)


def test_restaura_el_adaptador_que_apunta_a_nosotros(monkeypatch, en_windows):
    falso = _instalar(monkeypatch, _PowerShellFalso(UN_ADAPTADOR))

    resultado = net_config.restaurar_dns_automatico()

    assert resultado["restaurados"] == ["Wi-Fi"]
    assert resultado["error"] is None
    assert any("ResetServerAddresses" in c for c in falso.comandos)


def test_tambien_vacia_el_cache_de_nombres(monkeypatch, en_windows):
    """Sin esto, Windows sigue contestando desde su propio cache un rato y el
    arreglo parece no haber funcionado."""
    falso = _instalar(monkeypatch, _PowerShellFalso(UN_ADAPTADOR))

    net_config.restaurar_dns_automatico()

    assert any("Clear-DnsClientCache" in c for c in falso.comandos)


def test_no_toca_los_adaptadores_que_no_son_nuestros(monkeypatch, en_windows):
    """La diferencia con el comando manual que había que pegar en PowerShell:
    ese resetea TODOS los adaptadores activos, así que si tenés un DNS interno
    puesto a mano (el del trabajo, una VPN) te lo borra también. Acá solo se
    tocan los que apuntan a 127.0.0.1 o ::1."""
    falso = _instalar(monkeypatch, _PowerShellFalso("[]"))

    resultado = net_config.restaurar_dns_automatico()

    assert resultado["restaurados"] == []
    assert resultado["hacia_falta"] is False
    assert not any("Set-DnsClientServerAddress" in c for c in falso.comandos)
    # Y el filtro que se le manda a PowerShell nombra las dos direcciones.
    assert "127.0.0.1" in falso.comandos[0]
    assert "::1" in falso.comandos[0]


def test_un_solo_adaptador_no_rompe_el_parseo(monkeypatch, en_windows):
    """Windows PowerShell 5.1 devuelve un objeto suelto y no una lista cuando
    hay un solo resultado. Es el caso MÁS común (una sola placa de red), así
    que si no se contempla el arreglo falla justo donde más se usa."""
    _instalar(monkeypatch, _PowerShellFalso(UN_ADAPTADOR_SIN_ARRAY))

    assert net_config.restaurar_dns_automatico()["restaurados"] == ["Wi-Fi"]


def test_el_mismo_adaptador_no_se_cuenta_dos_veces(monkeypatch, en_windows):
    """Aparece repetido si tiene IPv4 e IPv6 apuntando a nosotros."""
    _instalar(monkeypatch, _PowerShellFalso(DUPLICADO))

    assert net_config.restaurar_dns_automatico()["restaurados"] == ["Wi-Fi"]


def test_restaura_todos_los_que_correspondan(monkeypatch, en_windows):
    _instalar(monkeypatch, _PowerShellFalso(DOS_ADAPTADORES))

    restaurados = net_config.restaurar_dns_automatico()["restaurados"]

    assert sorted(restaurados) == ["Ethernet", "Wi-Fi"]


def test_si_falla_lo_dice_y_da_el_comando(monkeypatch, en_windows, capsys):
    """Cambiar el DNS de una placa pide permisos de administrador. Si no los
    hay, quien lee el mensaje está justo sin poder navegar: no alcanza con un
    "falló", tiene que estar el comando para copiar y pegar."""
    _instalar(monkeypatch, _PowerShellFalso(UN_ADAPTADOR, falla_el_set="Acceso denegado"))

    resultado = net_config.restaurar_e_informar()
    salida = capsys.readouterr().out

    assert resultado["error"] == "Acceso denegado"
    assert resultado["restaurados"] == []
    assert "ADMINISTRADOR" in salida
    assert "ResetServerAddresses" in salida
    assert "flushdns" in salida


def test_una_respuesta_ilegible_no_lanza_excepcion(monkeypatch, en_windows):
    """Esto corre en el camino de apagado: que falle no puede impedir que el
    proceso termine."""
    _instalar(monkeypatch, _PowerShellFalso("{no es json"))

    assert net_config.restaurar_dns_automatico()["restaurados"] == []


def test_fuera_de_windows_no_hace_nada(monkeypatch):
    """En Linux/macOS el DNS se configura de otra forma y no es este proyecto
    el que lo cambia, así que tampoco le toca deshacerlo."""
    monkeypatch.setattr(net_config, "es_windows", lambda: False)
    falso = _instalar(monkeypatch, _PowerShellFalso(UN_ADAPTADOR))

    resultado = net_config.restaurar_dns_automatico()

    assert resultado["restaurados"] == []
    assert falso.comandos == []


# --------------------------------------------------- todos los caminos


def _fuente(nombre: str) -> str:
    raiz = Path(__file__).resolve().parent.parent
    return (raiz / nombre).read_text(encoding="utf-8")


def test_stop_dns_restaura_el_dns():
    """Es el que llama SecureCenter: era el camino por donde aparecía el bug."""
    fuente = _fuente("scripts/stop_dns.py")
    assert "net_config" in fuente
    assert "restaurar_e_informar" in fuente


def test_el_resolver_restaura_al_cerrarse():
    """Ctrl+C y el botón del panel salen por el mismo `finally`."""
    fuente = _fuente("scripts/run_dns.py")
    assert "net_config.restaurar_e_informar()" in fuente


def test_el_bat_no_tiene_su_propia_copia_del_reset():
    """El bug fue tener dos implementaciones y que solo una se usara en todos
    los caminos. Ahora el .bat llama al script en vez de resetear por su
    cuenta: si alguien vuelve a pegar el PowerShell acá, este test lo frena."""
    fuente = _fuente("SecureDNS.bat")
    lineas_activas = [
        linea for linea in fuente.splitlines()
        if not linea.strip().lower().startswith("rem")
    ]
    assert not any("ResetServerAddresses" in linea for linea in lineas_activas)
    assert any("stop_dns.py" in linea for linea in lineas_activas)
