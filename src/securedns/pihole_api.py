"""Hablarle a Pi-hole por la puerta que Pi-hole documenta, y por ninguna otra.

POR QUÉ EXISTE ESTE ARCHIVO

Porque a partir de acá Pi-hole es el que resuelve y el que bloquea, y
SecureDNS es el que le dice qué bloquear. Para eso hay que escribirle a
Pi-hole, y hay exactamente dos formas de hacerlo:

1. Meter un INSERT en `/etc/pihole/gravity.db`. Es lo que hace medio internet
   y funciona hoy.
2. Su API REST, que es lo que usa su propio panel web.

Este archivo hace lo segundo, y el motivo es el único que importa: la primera
se rompe. `gravity.db` es una base INTERNA de Pi-hole. Su esquema cambia entre
versiones mayores, y encima el propio `pihole -g` la reconstruye, así que lo
que escribas a mano puede desaparecer sin que nadie te avise. Todo el sentido
de meter Pi-hole abajo era dejar de mantener plomería: si la integración se
rompe con cada actualización, no ganaste nada, cambiaste un mantenimiento por
otro.

LAS TRES TRAMPAS QUE TIENE ESTA API, Y QUE ESTÁN RESUELTAS ACÁ

**El `type` va en la query, no en el cuerpo.** Para agregar una lista, el
endpoint es `POST /api/lists?type=block` y el cuerpo lleva `address`,
`comment` y `enabled`. Si mandás `type` adentro del JSON, Pi-hole contesta
"Invalid request: Specify type parameter". Es un error real y bastante
famoso: el módulo de Pi-hole de NixOS lo tuvo (issue 500852) y por eso las
listas no se agregaban.

**La sesión vence.** `POST /api/auth` devuelve un `sid` con una validez en
segundos. Si el proceso queda prendido y publica cada seis horas, para la
segunda vuelta el sid ya no sirve. Acá, ante un 401, se entra de nuevo y se
reintenta UNA vez. Sin eso, la publicación andaría el primer día y fallaría
en silencio a partir del segundo, que es la peor forma de fallar.

**`gravity` contesta texto en vivo, con códigos de color de terminal.** No es
JSON. Viene con secuencias ANSI adentro (issue 2671 de FTL), así que se
limpian antes de mostrarlas o de guardarlas en un log.

DÓNDE VA EL sid

En la cabecera `X-FTL-SID`. Pi-hole también lo acepta en la query string y en
una cookie, pero es la misma decisión que ya tomamos con la API de SecureHIPS:
un token en la URL termina escrito en logs de acceso, en el historial y en
cualquier proxy del medio. En una cabecera, no. Y con cookie haría falta
además el `X-FTL-CSRF`, que es complejidad de navegador que este cliente no
necesita.

LA CONTRASEÑA SALE DEL .env

Nunca del config.yaml, igual que el token de Telegram. Es la contraseña de la
aplicación (app password) que se genera desde el panel de Pi-hole, no la del
usuario: se puede revocar sola y funciona aunque tengas 2FA puesto.

LO QUE ESTE CLIENTE NO HACE

No borra listas, no toca grupos, no cambia la configuración de Pi-hole, no
lee sus consultas (eso es la fase 2, y va en solo lectura). Agrega su lista,
la mantiene, y pide una reconstrucción. Nada más. Cuanto menos superficie
toque, menos hay que revisar cuando Pi-hole saque una versión nueva.
"""

import json
import re
import time
from urllib.parse import quote, urlsplit

try:
    import requests
except ImportError:  # pragma: no cover - se avisa donde se usa
    requests = None

# Secuencias de color de terminal, para limpiar la salida de gravity.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")

# Cuánto antes de que venza la sesión se pide una nueva. Renovar justo en el
# límite es pedirle al reloj de dos máquinas que coincidan.
MARGEN_DE_SESION = 30.0

TIEMPO_ESPERA = 20.0
# gravity reconstruye el árbol entero: con listas grandes tarda minutos, no
# segundos. Con el timeout normal se cortaría a la mitad y quedaría la duda de
# si terminó o no.
TIEMPO_ESPERA_GRAVITY = 600.0


def limpiar_ansi(texto: str) -> str:
    """Saca los códigos de color que Pi-hole manda en la salida de gravity."""
    return _ANSI.sub("", texto or "")


def resumen_de_gravity(salida: str) -> str:
    """Las líneas que realmente dicen algo, de todo lo que escupe gravity.

    Se queda con las que hablan de cantidades y con las de error. El resto es
    la barra de progreso, que en una terminal se ve bien y en un log es ruido.
    """
    utiles = []
    for linea in limpiar_ansi(salida).splitlines():
        limpia = linea.strip()
        if not limpia:
            continue
        bajo = limpia.lower()
        if ("domains" in bajo or "dominios" in bajo or "error" in bajo
                or "warning" in bajo or "failed" in bajo):
            utiles.append(limpia)
    return " | ".join(utiles[-6:])


def _url_valida(url: str) -> bool:
    """Solo http o https, y con host. Una URL rara acá es una petición a
    cualquier lado llevando la contraseña de Pi-hole adentro."""
    partes = urlsplit((url or "").strip())
    return partes.scheme in ("http", "https") and bool(partes.netloc)


class ClientePihole:
    """El cliente. Ninguno de sus métodos lanza: todos devuelven (ok, detalle).

    Es la misma convención que el resto de la suite. Publicar listas es una
    tarea de fondo: que Pi-hole esté apagado no puede tirar abajo al proceso
    que la ejecuta.
    """

    def __init__(self, url: str, password: str, *, verificar_tls: bool = True,
                 timeout: float = TIEMPO_ESPERA):
        self.url = (url or "").strip().rstrip("/")
        self.password = password or ""
        self.verificar_tls = bool(verificar_tls)
        self.timeout = timeout
        self.sid = ""
        self._vence = 0.0

    # ------------------------------------------------------------- interno

    def _listo(self) -> tuple[bool, str]:
        if requests is None:  # pragma: no cover
            return False, "falta la librería requests (pip install -r requirements.txt)"
        if not _url_valida(self.url):
            return False, f"la url de Pi-hole no sirve: {self.url or '(vacía)'}"
        if not self.password:
            return False, ("no hay contraseña de Pi-hole. Generá una app password "
                           "en su panel y ponela en el .env como PIHOLE_PASSWORD")
        return True, ""

    def _sesion_viva(self) -> bool:
        return bool(self.sid) and time.time() < self._vence

    def entrar(self, forzar: bool = False) -> tuple[bool, str]:
        """POST /api/auth. Guarda el sid y cuándo vence."""
        if not forzar and self._sesion_viva():
            return True, "sesión vigente"
        ok, motivo = self._listo()
        if not ok:
            return False, motivo
        try:
            respuesta = requests.post(
                f"{self.url}/api/auth",
                json={"password": self.password},
                timeout=self.timeout, verify=self.verificar_tls,
            )
        except Exception as exc:  # noqa: BLE001
            return False, f"no pude llegar a Pi-hole en {self.url}: {exc}"
        if respuesta.status_code == 401:
            # Se dice qué pasó pero NO se repite la contraseña en el mensaje:
            # este texto termina en el panel y en el log.
            return False, "Pi-hole rechazó la contraseña (¿es la app password?)"
        if respuesta.status_code >= 400:
            return False, f"Pi-hole contestó {respuesta.status_code} al entrar"
        try:
            datos = respuesta.json().get("session") or {}
        except ValueError:
            return False, "Pi-hole contestó algo que no es JSON al entrar"
        sid = datos.get("sid") or ""
        if not sid:
            # Pasa cuando Pi-hole no tiene contraseña puesta: contesta 200 y
            # `valid: true` sin sid. Decirlo es mejor que fallar después con
            # un 401 confuso en cada pedido.
            return False, ("Pi-hole no devolvió una sesión. Si no tiene "
                           "contraseña puesta, ponele una: publicar listas "
                           "sin autenticación no es una opción")
        self.sid = sid
        self._vence = time.time() + float(datos.get("validity") or 300) - MARGEN_DE_SESION
        return True, "sesión abierta"

    def salir(self) -> None:
        """DELETE /api/auth. Sin sesiones colgadas al terminar."""
        if not self.sid or requests is None:
            return
        try:
            requests.delete(f"{self.url}/api/auth",
                            headers={"X-FTL-SID": self.sid},
                            timeout=self.timeout, verify=self.verificar_tls)
        except Exception:  # noqa: BLE001 - cerrar sesión no puede hacer ruido
            pass
        self.sid = ""
        self._vence = 0.0

    def _pedir(self, metodo: str, ruta: str, *, cuerpo=None, stream: bool = False,
               timeout: float | None = None, _reintento: bool = False):
        """Un pedido autenticado, con UN reintento si la sesión venció.

        El reintento es lo que hace que esto sirva en un proceso que queda
        prendido días. Sin él, la primera publicación anda y las siguientes
        fallan con 401 cuando ya nadie está mirando la consola.
        """
        ok, motivo = self.entrar()
        if not ok:
            return None, motivo
        try:
            respuesta = requests.request(
                metodo, f"{self.url}{ruta}",
                headers={"X-FTL-SID": self.sid},
                json=cuerpo, stream=stream,
                timeout=timeout or self.timeout, verify=self.verificar_tls,
            )
        except Exception as exc:  # noqa: BLE001
            return None, f"{metodo} {ruta} falló: {exc}"
        if respuesta.status_code == 401 and not _reintento:
            self.sid = ""
            self._vence = 0.0
            ok, motivo = self.entrar(forzar=True)
            if not ok:
                return None, f"la sesión venció y no pude renovarla: {motivo}"
            return self._pedir(metodo, ruta, cuerpo=cuerpo, stream=stream,
                               timeout=timeout, _reintento=True)
        return respuesta, ""

    # ------------------------------------------------------------- listas

    def listas(self, tipo: str = "block") -> tuple[list | None, str]:
        """GET /api/lists?type=block. Las adlists que Pi-hole ya tiene."""
        respuesta, error = self._pedir("GET", f"/api/lists?type={quote(tipo)}")
        if respuesta is None:
            return None, error
        if respuesta.status_code >= 400:
            return None, f"Pi-hole contestó {respuesta.status_code} al listar"
        try:
            return list(respuesta.json().get("lists") or []), ""
        except ValueError:
            return None, "Pi-hole contestó algo que no es JSON al listar"

    def tiene_lista(self, address: str, tipo: str = "block") -> tuple[bool | None, str]:
        """¿Esta dirección ya está registrada como adlist?"""
        listas, error = self.listas(tipo)
        if listas is None:
            return None, error
        objetivo = (address or "").strip()
        return any((l.get("address") or "").strip() == objetivo for l in listas), ""

    def agregar_lista(self, address: str, comentario: str = "",
                      tipo: str = "block") -> tuple[bool, str]:
        """POST /api/lists?type=block

        OJO con dónde va cada cosa: `type` en la query string, y `address`,
        `comment` y `enabled` en el cuerpo. Mandar `type` adentro del JSON es
        el error que hace que Pi-hole conteste "Invalid request: Specify type
        parameter" y que la lista no se agregue nunca.
        """
        respuesta, error = self._pedir(
            "POST", f"/api/lists?type={quote(tipo)}",
            cuerpo={"address": address, "comment": comentario, "enabled": True},
        )
        if respuesta is None:
            return False, error
        if respuesta.status_code in (200, 201):
            return True, f"lista registrada en Pi-hole: {address}"
        if respuesta.status_code == 409:
            # Ya estaba. No es un error: es el caso normal de la segunda vuelta.
            return True, "la lista ya estaba registrada"
        return False, (f"Pi-hole contestó {respuesta.status_code} al agregar la "
                       f"lista: {_texto_corto(respuesta)}")

    def asegurar_lista(self, address: str, comentario: str = "",
                       tipo: str = "block") -> tuple[bool, str]:
        """Que la lista esté, la haya puesto quien la haya puesto.

        Se pregunta antes de agregar en vez de agregar y ver qué pasa, porque
        así el mensaje distingue "la acabo de registrar" de "ya estaba", y esa
        diferencia es la que uno quiere leer en el panel.
        """
        esta, error = self.tiene_lista(address, tipo)
        if esta is None:
            return False, error
        if esta:
            return True, "la lista ya estaba registrada en Pi-hole"
        return self.agregar_lista(address, comentario, tipo)

    # ------------------------------------------------------------- gravity

    def gravity(self) -> tuple[bool, str]:
        """POST /api/action/gravity: que Pi-hole reconstruya con las listas.

        Contesta texto en vivo, no JSON, y con códigos de color adentro. Se
        lee entero (puede tardar minutos con listas grandes) y se resume.
        """
        respuesta, error = self._pedir("POST", "/api/action/gravity", stream=True,
                                       timeout=TIEMPO_ESPERA_GRAVITY)
        if respuesta is None:
            return False, error
        if respuesta.status_code >= 400:
            return False, f"Pi-hole contestó {respuesta.status_code} al correr gravity"
        try:
            salida = respuesta.text
        except Exception as exc:  # noqa: BLE001
            return False, f"gravity arrancó pero se cortó la lectura: {exc}"
        resumen = resumen_de_gravity(salida)
        return True, resumen or "gravity terminó (sin detalle)"


def _texto_corto(respuesta, tope: int = 200) -> str:
    """El cuerpo del error, acotado. Pi-hole devuelve un JSON con `error`."""
    try:
        datos = respuesta.json()
    except (ValueError, AttributeError):
        return (getattr(respuesta, "text", "") or "")[:tope]
    if isinstance(datos, dict) and isinstance(datos.get("error"), dict):
        error = datos["error"]
        return f"{error.get('message', '')} {error.get('hint', '')}".strip()[:tope]
    return json.dumps(datos)[:tope]
