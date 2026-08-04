"""Envío de alertas por Telegram cuando el resolver detecta algo.

Es el mismo módulo de SecureProxy con una diferencia: allá los pedidos
salientes se hacen con un cliente HTTP propio, porque el proxy es el proxy del
sistema y `requests` respeta esa configuración, así que cada alerta se la
mandaba a sí mismo y armaba un bucle.

Acá eso no pasa (un resolver DNS no es un proxy HTTP), pero existe la versión
DNS del mismo problema: si SecureDNS es el DNS del sistema y alguna lista
llegara a bloquear `api.telegram.org`, el resolver no podría avisar de nada
nunca más. Eso se resuelve del otro lado, en `dns_server.py`: ver
`DOMINIOS_PROPIOS`.
"""

import threading

import requests


class TelegramNotifier:
    API_URL_TEMPLATE = "https://api.telegram.org/bot{token}/sendMessage"

    # Techo de envíos en vuelo. Si Telegram no responde y el resolver está
    # bloqueando mucho, no tiene sentido acumular hilos esperando.
    MAX_EN_VUELO = 8

    def __init__(self, enabled: bool, bot_token: str, chat_id: str):
        self.enabled = enabled and bool(bot_token) and bool(chat_id)
        self.bot_token = bot_token
        self.chat_id = chat_id
        self._en_vuelo = 0
        self._lock = threading.Lock()

    def send_alert(self, message: str) -> None:
        """Manda la alerta SIN esperarla.

        Antes esto era una llamada de red sincrónica con 5 segundos de
        timeout, hecha en el mismo hilo que atiende la conexión y justo
        antes de responderle al cliente. O sea: con Telegram lento o
        inalcanzable -que es exactamente lo que pasa cuando la red anda
        mal- cada bloqueo demoraba 5 segundos el 403, y una ráfaga de
        bloqueos dejaba al navegador colgado. El aviso de escritorio ya se
        había hecho asincrónico por este mismo motivo; esto quedó atrás.
        """
        if not self.enabled:
            return
        with self._lock:
            if self._en_vuelo >= self.MAX_EN_VUELO:
                return
            self._en_vuelo += 1
        threading.Thread(target=self._enviar, args=(message,), daemon=True).start()

    def _enviar(self, message: str) -> None:
        try:
            requests.post(
                self.API_URL_TEMPLATE.format(token=self.bot_token),
                data={"chat_id": self.chat_id, "text": message},
                timeout=5,
            )
        except requests.RequestException:
            # Una alerta que falla no debería tumbar el resolver.
            pass
        finally:
            with self._lock:
                self._en_vuelo -= 1
