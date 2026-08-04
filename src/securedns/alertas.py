"""Avisos cuando algo cruza un umbral, no cuando pasa cualquier cosa.

POR QUÉ NO SE AVISA DE CADA BLOQUEO

SecureProxy avisa por bloqueo, y ahí tiene sentido: un proxy de una sola
máquina bloquea poco. Un resolver que atiende a toda la casa con la lista de
publicidad activada bloquea **miles** de consultas por día. Un aviso por
bloqueo sería una notificación cada pocos segundos, y una herramienta que te
tapa la pantalla se apaga a la semana. Apagada no avisa nada, así que el
resultado neto de avisar demasiado es avisar menos.

Entonces acá se avisa por **cambios**, no por eventos:

- Un pico de bloqueos: muchos más de lo habitual en poco tiempo.
- Malware o phishing, que sí son de a poquitos y cada uno importa.
- Un hallazgo nuevo de la pestaña Detección (tunneling, actividad anómala).

QUÉ NO HACE

No decide nada. Mirar y avisar; el bloqueo lo hace el resolver por su cuenta
y las detecciones señalan sin cortar (ADR 0004). Si el motor de alertas falla
o está apagado, el resolver funciona exactamente igual.
"""

import threading
import time

# Cada cuánto se revisan los umbrales. Un minuto es suficiente: lo que se
# quiere detectar son cambios sostenidos, no ráfagas de dos segundos.
INTERVALO = 60

# Cuántas veces por encima de lo habitual tiene que estar el ritmo de bloqueos
# del último minuto para que valga la pena avisar.
FACTOR_PICO = 5.0

# Piso absoluto de bloqueos en el minuto. Sin esto, pasar de 1 bloqueo por
# minuto a 6 dispararía un aviso que no le importa a nadie.
MINIMO_BLOQUEOS = 50

# Categorías que avisan de a una, sin esperar a que haya un pico. Publicidad y
# tracking quedan afuera a propósito: son ruido de fondo y avisar de cada
# anuncio bloqueado es exactamente la forma de que apagues los avisos.
CATEGORIAS_GRAVES = ("malware", "phishing")

# Cuánto tiene que pasar para repetir el MISMO aviso. Una hora: si el problema
# sigue, ya te enteraste, y repetirlo cada minuto no agrega información.
SILENCIO_POR_AVISO = 3600

# Techo duro de avisos por hora, pase lo que pase.
TOPE_POR_HORA = 6


class MotorDeAlertas:
    """Revisa el estado cada minuto y avisa lo que cambió."""

    def __init__(self, logger_db, telegram=None, escritorio=None, enabled: bool = True):
        self.logger_db = logger_db
        self.telegram = telegram
        self.escritorio = escritorio
        self.enabled = enabled
        self._lock = threading.Lock()
        # clave del aviso -> momento en que se mandó
        self._enviados: dict[str, float] = {}
        # Hallazgos que ya se avisaron, para no repetirlos en cada vuelta.
        # Con techo: sin él crece para siempre en un proceso que corre meses.
        self._hallazgos_vistos: set[str] = set()
        self.MAX_VISTOS = 500
        self._ultimo_id = 0

    # ---------- control de repetición ----------

    def _puede_avisar(self, clave: str) -> bool:
        ahora = time.time()
        with self._lock:
            self._enviados = {
                k: t for k, t in self._enviados.items() if ahora - t < 3600
            }
            if len(self._enviados) >= TOPE_POR_HORA:
                return False
            ultimo = self._enviados.get(clave)
            if ultimo is not None and ahora - ultimo < SILENCIO_POR_AVISO:
                return False
            self._enviados[clave] = ahora
            return True

    def _avisar(self, clave: str, titulo: str, cuerpo: str) -> bool:
        """Manda el aviso por los canales que estén activos. True si se mandó."""
        if not self.enabled or not self._puede_avisar(clave):
            return False
        if self.telegram is not None:
            try:
                self.telegram.send_alert(f"[SecureDNS] {titulo}\n{cuerpo}")
            except Exception:  # noqa: BLE001 - un canal caído no frena al otro
                pass
        if self.escritorio is not None:
            try:
                self.escritorio.mostrar(titulo, cuerpo)
            except Exception:  # noqa: BLE001
                pass
        return True

    # ---------- los umbrales ----------

    def revisar(self) -> list[str]:
        """Una vuelta de revisión. Devuelve las claves de lo que se avisó.

        Devuelve la lista en vez de no devolver nada para poder testearlo sin
        mandar notificaciones de verdad.
        """
        avisados = []
        for comprobar in (self._pico_de_bloqueos, self._categorias_graves,
                          self._hallazgos_nuevos):
            try:
                avisados.extend(comprobar())
            except Exception:  # noqa: BLE001 - una alerta rota no tumba el resolver
                continue
        return avisados

    def _pico_de_bloqueos(self) -> list[str]:
        ritmo = self.logger_db.ritmo_de_bloqueos()
        ultimo = ritmo["ultimo_minuto"]
        base = ritmo["por_minuto_habitual"]
        if ultimo < MINIMO_BLOQUEOS or base <= 0 or ultimo < base * FACTOR_PICO:
            return []
        if self._avisar(
            "pico-de-bloqueos",
            "Pico de bloqueos",
            f"{ultimo} consultas bloqueadas en el último minuto, contra "
            f"{base:.0f} por minuto que es lo habitual. Mirá el panel para ver "
            "qué equipo y qué dominios.",
        ):
            return ["pico-de-bloqueos"]
        return []

    def _categorias_graves(self) -> list[str]:
        """Malware y phishing avisan de a uno: son pocos y cada uno importa.

        Se mira solo lo registrado DESPUÉS del último id visto, así que un
        bloqueo se evalúa una sola vez aunque el motor corra cada minuto.
        """
        filas, ultimo_id = self.logger_db.bloqueos_desde(self._ultimo_id)
        self._ultimo_id = ultimo_id
        avisados = []
        for fila in filas:
            categoria = (fila.get("category") or "").lower()
            if categoria not in CATEGORIAS_GRAVES:
                continue
            dominio = fila.get("domain") or ""
            clave = f"grave:{categoria}:{dominio}"
            if self._avisar(
                clave,
                f"Bloqueado: {categoria}",
                f"{dominio}\nLo consultó {fila.get('client_ip') or 'un equipo de la red'}.",
            ):
                avisados.append(clave)
        return avisados

    def _hallazgos_nuevos(self) -> list[str]:
        avisados = []
        for grupo in self.logger_db.tunneling(24):
            clave = f"tunel:{grupo['cliente']}:{grupo['padre']}"
            if clave in self._hallazgos_vistos:
                continue
            motivos = "\n".join(f"- {s}" for s in grupo["senales"])
            # Se marca como visto SOLO si el aviso salió de verdad. Antes se
            # marcaba antes de intentar, así que un hallazgo que se topaba con
            # el techo de avisos por hora quedaba silenciado para siempre. Y
            # como los bloqueos de malware se revisan primero, los que se
            # comían la cuota eran ellos y lo que se perdía era justamente la
            # detección de tunneling, que es lo más importante que tenemos.
            if self._avisar(
                clave,
                "Posible tunneling por DNS",
                f"{grupo['padre']} desde {grupo['cliente']}\n{motivos}",
            ):
                self._recordar(clave)
                avisados.append(clave)
        for hallazgo in self.logger_db.actividad_anomala(24):
            clave = f"anomalia:{hallazgo['cliente']}"
            if clave in self._hallazgos_vistos:
                continue
            if self._avisar(
                clave,
                "Actividad fuera de lo normal",
                f"{hallazgo['cliente']} hizo {hallazgo['ultima_hora']} consultas en la "
                f"última hora, {hallazgo['factor']:.1f} veces su ritmo habitual.",
            ):
                self._recordar(clave)
                avisados.append(clave)
        return avisados

    def _recordar(self, clave: str) -> None:
        if len(self._hallazgos_vistos) >= self.MAX_VISTOS:
            self._hallazgos_vistos.clear()
        self._hallazgos_vistos.add(clave)

    # ---------- el hilo ----------

    def correr_en_segundo_plano(self) -> threading.Thread:
        def bucle():
            # Una vuelta en falso al arrancar: así el `_ultimo_id` queda en el
            # final del historial y no se avisa de bloqueos viejos como si
            # acabaran de pasar.
            try:
                _filas, ultimo = self.logger_db.bloqueos_desde(0)
                self._ultimo_id = ultimo
            except Exception:  # noqa: BLE001
                pass
            while True:
                time.sleep(INTERVALO)
                self.revisar()

        hilo = threading.Thread(target=bucle, daemon=True)
        hilo.start()
        return hilo
