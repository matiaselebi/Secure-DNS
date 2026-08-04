"""Hallazgos de detección marcados como normales.

POR QUÉ HACE FALTA ESTO

La pestaña Detección no mira una lista de dominios malos: mira la FORMA del
tráfico. Eso es lo que la hace capaz de encontrar cosas que ningún feed
conoce, y es también lo que garantiza que alguna vez se equivoque.

El caso de manual es un CDN de video. `googlevideo.com` genera nombres como
`rr3---sn-4g5e6nz7.googlevideo.com`: uno distinto por servidor y por sesión,
largos, y con una parte variable que no se parece a ninguna palabra. Contra un
detector de tunneling eso da dos señales de cinco, que es exactamente el mínimo
para marcar el grupo. El detector no está fallando: está describiendo bien un
tráfico que, casualmente, tiene la misma forma que un túnel. Lo que falta es
que alguien mire el hallazgo una vez y diga "esto es YouTube".

POR QUÉ NO SE RESUELVE CON UNA LISTA INTERNA DE CDNs

Sería más fácil traer una lista de dominios conocidos (Google, Akamai,
Cloudflare, Fastly) y saltearlos. Y sería peor por dos razones. La primera es
que un atacante que sepa que existe esa lista tunelea bajo un nombre que esté
en ella. La segunda, más importante: el ruido de cada red es distinto, y una
lista que yo elija a dedo va a estar siempre incompleta para la red de otro y
de más para la mía. La decisión de qué es normal la tiene que tomar quien mira
el panel, que es el único que sabe qué hay en su red.

QUÉ NO ES ESTO

No es una lista blanca. Marcar `googlevideo.com` como normal NO lo saca de la
blocklist ni cambia una sola decisión de resolución: si mañana entra a un feed
de amenazas, se bloquea igual. Lo único que hace es dejar de marcar el patrón
como hallazgo y, en consecuencia, de restar puntos. Sigue todo registrado y
sigue todo consultable en el historial.

Está separado de la lista de ruido (`view_prefs.py`) a propósito. Aquella
esconde consultas de la vista; esta silencia un hallazgo pero no esconde nada:
las consultas se siguen viendo enteras en el historial.
"""

from .blocklist import Blocklist


class HallazgosNormales:
    """Los dominios padre cuyo patrón ya fue revisado y es esperable.

    Se guarda por dominio padre y no por (equipo, dominio) a propósito: si
    `googlevideo.com` es normal desde la notebook, también lo es desde el
    teléfono, y obligar a marcarlo una vez por dispositivo sería un trámite sin
    ninguna ganancia de precisión.
    """

    def __init__(self, path: str | None = None):
        # Se reutiliza Blocklist porque el matcheo que hace falta es el mismo
        # (dominio exacto o subdominio) y ya está probado, incluidos el punto
        # final y el punycode. Un `set` pelado se comería
        # `googlevideo.com.` como si fuera otro dominio.
        self._lista = Blocklist(path) if path else None

    def es_normal(self, padre: str) -> bool:
        if self._lista is None or not padre:
            return False
        return self._lista.is_blocked(padre)

    def marcar(self, padre: str) -> bool:
        if self._lista is None or not padre:
            return False
        self._lista.add_and_reload(padre)
        return True

    def volver_a_vigilar(self, padre: str) -> bool:
        if self._lista is None or not padre:
            return False
        self._lista.remove_and_reload(padre)
        return True

    def marcados(self) -> list[str]:
        """Los dominios marcados, para poder verlos y revertirlos desde el
        panel. Silenciar avisos sin poder ver qué silenciaste es cómo un panel
        de seguridad termina en verde por acumulación de decisiones que nadie
        recuerda haber tomado."""
        if self._lista is None:
            return []
        return self._lista.manual_entries()

    def filtrar(self, grupos: list[dict]) -> list[dict]:
        """Saca de los hallazgos los grupos ya marcados como normales.

        Se aplica en un solo lugar (el cache de hallazgos del panel) para que
        la pestaña, el puntaje, el resumen y la API no puedan mostrar tres
        números distintos.
        """
        if self._lista is None:
            return grupos
        return [g for g in grupos if not self.es_normal(g.get("padre") or "")]
