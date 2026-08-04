"""Avisos en el escritorio, sin depender de ningún servicio externo.

Hasta acá el único aviso que tenía el resolver era por Telegram, y eso deja
afuera a cualquiera que no use Telegram: en la práctica el resolver bloqueaba
cosas y vos te enterabas si te acordabas de abrir el panel. Una herramienta
de seguridad que solo avisa cuando la mirás no avisa.

Cómo se manda la notificación, sin dependencias nuevas:

- **Windows**: PowerShell armando un `NotifyIcon` de WinForms, que es la
  forma que anda en todas las versiones desde Windows 7 sin instalar nada.
  Las notificaciones "toast" modernas quedan mejor pero necesitan que la
  app esté registrada en el sistema, que es mucho trámite para esto.
- **Linux**: `notify-send`, si está.

Tres cosas que hacen que esto no se vuelva molesto, que es la forma más
rápida de que alguien apague las alertas y se quede sin ninguna:

1. **No se avisa de todo.** Solo de lo que significa algo: una IP de C2, un
   pool de minería, una IP con mala reputación. Un dominio de la blocklist
   manual no dispara nada, porque de eso ya sabés.
2. **Un aviso por dominio cada tanto.** Si un proceso golpea el mismo pool
   200 veces por minuto, eso es UN aviso, no doscientos.
3. **Un techo por hora.** Si algo sale muy mal, preferimos perder avisos
   antes que tapar la pantalla.

Y todo el envío pasa por un hilo aparte: lanzar PowerShell tarda cientos de
milisegundos, y eso no puede estar en el camino de una conexión.
"""

import platform
import queue
import subprocess
import threading
import time

ES_WINDOWS = platform.system() == "Windows"

# Motivos que ameritan interrumpir a alguien. El resto queda en el panel.
#
# Las claves son frases y no palabras sueltas a propósito: con "tor" a secas,
# bloquear "torproject.org" desde la lista manual dispararía un aviso de
# "nodo TOR" que no es cierto, y con "c2" alcanzaría con que un dominio
# tuviera esas dos letras. Un aviso que miente es peor que no avisar.
MOTIVOS_QUE_AVISAN = (
    "servidor de c2",
    "pool de minería",
    "pool de mineria",
    "cryptojacking",
    "score de abuso",
    "mala reputación",
    "mala reputacion",
    "nodo de salida tor",
)

# Cuánto tiene que pasar para volver a avisar del MISMO dominio.
SILENCIO_POR_DOMINIO = 600  # 10 minutos

# Techo de avisos por hora, pase lo que pase.
TOPE_POR_HORA = 12


class DesktopNotifier:
    """Notificaciones del sistema, con freno para que no se vuelvan ruido."""

    def __init__(self, enabled: bool = True, solo_graves: bool = True):
        self.enabled = enabled
        self.solo_graves = solo_graves
        self._ultimo_por_dominio: dict[str, float] = {}
        self._enviados: list[float] = []
        self._lock = threading.Lock()
        self._cola: queue.Queue = queue.Queue(maxsize=32)
        self._hilo = None
        # Se separa "el sistema puede mostrar notificaciones" de "están
        # activadas". Si fueran una sola cosa, apagarlas y volver a
        # prenderlas desde el panel las dejaría rotas para siempre.
        self._soportado = ES_WINDOWS or _hay_notify_send()

    @property
    def disponible(self) -> bool:
        return bool(self.enabled and self._soportado)

    # ---------- decisión ----------

    def merece_aviso(self, motivo: str) -> bool:
        """¿Este bloqueo amerita interrumpir a alguien?"""
        if not self.solo_graves:
            return True
        motivo = (motivo or "").lower()
        return any(clave in motivo for clave in MOTIVOS_QUE_AVISAN)

    def _puede_avisar(self, dominio: str) -> bool:
        ahora = time.time()
        with self._lock:
            self._enviados = [t for t in self._enviados if ahora - t < 3600]
            if len(self._enviados) >= TOPE_POR_HORA:
                return False
            ultimo = self._ultimo_por_dominio.get(dominio, 0)
            if ahora - ultimo < SILENCIO_POR_DOMINIO:
                return False
            self._ultimo_por_dominio[dominio] = ahora
            self._enviados.append(ahora)
            return True

    # ---------- envío ----------

    def mostrar(self, titulo: str, cuerpo: str) -> bool:
        """Encola un aviso ya armado, sin pasar por el filtro de motivos.

        Existe porque en SecureDNS los avisos no salen de cada bloqueo sino del
        motor de umbrales (ver `alertas.py`), que ya decidió que esto merece un
        aviso y ya aplicó su propio antirrepetición. Volver a filtrarlo acá con
        las frases pensadas para el proxy lo dejaría afuera.

        Nunca bloquea: si la cola está llena, se descarta el aviso. Perder un
        aviso es preferible a demorar el resolver.
        """
        if not self.disponible:
            return False
        try:
            self._cola.put_nowait((titulo, cuerpo))
        except queue.Full:
            return False
        self._asegurar_hilo()
        return True

    def avisar_bloqueo(self, host: str, motivo: str, proceso: str = "") -> bool:
        """Encola un aviso. Devuelve si se va a mandar o si se frenó.

        Nunca bloquea: si la cola está llena porque algo se disparó, se
        descarta el aviso. Perder un aviso es preferible a demorar una
        conexión.
        """
        if not self.disponible or not self.merece_aviso(motivo):
            return False
        if not self._puede_avisar(host):
            return False

        cuerpo = f"{host}\n{motivo}"
        if proceso:
            cuerpo += f"\nProceso: {proceso}"
        try:
            self._cola.put_nowait(("SecureDNS bloqueó una conexión", cuerpo))
        except queue.Full:
            return False
        self._asegurar_hilo()
        return True

    def _asegurar_hilo(self) -> None:
        with self._lock:
            if self._hilo is None or not self._hilo.is_alive():
                self._hilo = threading.Thread(target=self._trabajar, daemon=True)
                self._hilo.start()

    def _trabajar(self) -> None:
        while True:
            try:
                titulo, cuerpo = self._cola.get(timeout=30)
            except queue.Empty:
                return
            try:
                self._mostrar(titulo, cuerpo)
            except Exception:
                # Un aviso que falla no puede tumbar nada.
                pass

    def _mostrar(self, titulo: str, cuerpo: str) -> None:
        if ES_WINDOWS:
            self._mostrar_windows(titulo, cuerpo)
        else:
            self._mostrar_linux(titulo, cuerpo)

    def _mostrar_windows(self, titulo: str, cuerpo: str) -> None:
        # Se arma con WinForms porque es lo que anda en cualquier Windows sin
        # instalar nada. El icono se toma del propio PowerShell para no tener
        # que distribuir un .ico.
        seguro_titulo = titulo.replace("'", "''")
        seguro_cuerpo = cuerpo.replace("'", "''").replace("\n", " | ")
        script = (
            "[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');"
            "$n = New-Object System.Windows.Forms.NotifyIcon;"
            "$n.Icon = [System.Drawing.SystemIcons]::Warning;"
            f"$n.BalloonTipTitle = '{seguro_titulo}';"
            f"$n.BalloonTipText = '{seguro_cuerpo}';"
            "$n.Visible = $true;"
            "$n.ShowBalloonTip(10000);"
            "Start-Sleep -Seconds 10;"
            "$n.Dispose()"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
             "-Command", script],
            capture_output=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    def _mostrar_linux(self, titulo: str, cuerpo: str) -> None:
        subprocess.run(
            ["notify-send", "-u", "critical", "-a", "SecureDNS", titulo, cuerpo],
            capture_output=True, timeout=15,
        )

    # ---------- para el panel ----------

    def estado(self) -> dict:
        with self._lock:
            recientes = len([t for t in self._enviados if time.time() - t < 3600])
        if not self.enabled:
            return {"ok": False, "motivo": "desactivadas", "ayuda": ""}
        if not self.disponible:
            ayuda = "" if self._soportado else "instalá notify-send (paquete libnotify-bin)"
            return {"ok": False, "motivo": "no disponible acá", "ayuda": ayuda}
        return {
            "ok": True,
            "motivo": f"{recientes} en la última hora",
            "ayuda": "solo bloqueos graves" if self.solo_graves else "todos los bloqueos",
        }


def _hay_notify_send() -> bool:
    try:
        subprocess.run(["notify-send", "--version"], capture_output=True, timeout=5)
        return True
    except (OSError, subprocess.SubprocessError):
        return False
