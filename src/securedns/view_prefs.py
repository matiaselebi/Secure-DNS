"""Lo que se MUESTRA en el panel, separado de lo que se BLOQUEA.

Esta distinción es el punto entero del módulo. El motor de filtrado decide
qué consulta pasa y cuál no; esto decide qué consultas tapan la vista. Son
dos cosas distintas y conviene que vivan en archivos distintos, porque
mezclarlas es como termina un panel de seguridad escondiendo justo lo que
tenía que mostrar.

El problema concreto: el resolver del sistema ve TODO lo que hace la máquina,
y buena parte de eso es ruido previsible. El navegador pregunta cientos de
veces por día si hay internet, Windows chequea actualizaciones, cada TLS
consulta si un certificado sigue vigente. Con eso, el "Top 10 de destinos"
son diez dominios de comprobación y no se ve si apareció algo raro. Peor
todavía si bloqueaste la telemetría a mano: cada uno de esos chequeos suma
un bloqueo, y el historial se llena de la misma línea repetida.

La solución es un filtro de VISTA. Tres reglas que lo hacen honesto:

1. No cambia nada de lo que se guarda. La base sigue teniendo todo.
2. El panel dice siempre cuántas consultas está ocultando.
3. Buscar un dominio ignora el filtro: si lo estás auditando, lo ves entero.

Y se apaga con un botón, sin reiniciar. Que apagarlo y prenderlo sea
instantáneo tiene su truco: la marca de "esto es ruido" se escribe en cada
consulta al registrarla, siempre, esté el filtro encendido o no. Así el
botón solo cambia si la consulta mira esa columna, y no tiene que recorrer
todo el historial cada vez.
"""


class PreferenciasDeVista:
    """Qué se oculta del panel. No participa de ninguna decisión de bloqueo."""

    def __init__(self, noise_list=None, ocultar_ruido: bool = True):
        # `noise_list` es una Blocklist cargada desde data/noisy_domains.txt.
        # Se reutiliza esa clase porque el matcheo que hace falta es el mismo
        # (dominio exacto o subdominio) y ya está probado.
        self.noise_list = noise_list
        self.ocultar_ruido = ocultar_ruido

    def es_ruidoso(self, host: str) -> bool:
        if self.noise_list is None:
            return False
        return self.noise_list.is_blocked(host)

    def agregar(self, dominio: str) -> bool:
        """Suma un dominio a la lista de ruido. True si se pudo.

        Existe para que se pueda hacer desde el panel: la lista que viene
        de fábrica cubre el ruido de sistema (Windows, certificados, NTP),
        pero el ruido de CADA máquina es distinto. Si en tu Top 10 vive
        `desktop.docker.com` porque tenés Docker abierto todo el día, eso no
        va a estar nunca en una lista genérica, y editar un .txt a mano para
        sacarlo es demasiado trabajo para algo que se hace de un vistazo.
        """
        if self.noise_list is None or not dominio:
            return False
        self.noise_list.add_and_reload(dominio)
        return True

    def quitar(self, dominio: str) -> bool:
        """Saca un dominio de la lista manual de ruido."""
        if self.noise_list is None or not dominio:
            return False
        self.noise_list.remove_and_reload(dominio)
        return True

    def dominios_manuales(self) -> list[str]:
        """Los dominios de la lista, para poder verlos y editarlos desde el
        panel. Ocultar cosas sin poder ver qué ocultaste sería la mitad mala
        de esta funcionalidad."""
        if self.noise_list is None:
            return []
        return self.noise_list.manual_entries()

    @property
    def cantidad_de_dominios(self) -> int:
        """Cuántos dominios tiene la lista, esté activa o no. Para el panel:
        'ocultando 47 dominios de telemetría' explica de dónde sale el filtro."""
        if self.noise_list is None:
            return 0
        return len(self.noise_list.dominios())
