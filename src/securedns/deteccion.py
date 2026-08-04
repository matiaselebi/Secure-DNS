"""Detección de tunneling por DNS y de actividad anómala.

QUÉ ES EL TUNNELING POR DNS Y POR QUÉ IMPORTA ACÁ

El DNS casi nunca está bloqueado. Aunque una red corte todo lo demás, las
consultas de nombres suelen pasar, porque sin ellas no anda nada. Eso lo
convierte en un canal de salida: si un programa quiere sacar datos de una red
sin que un firewall lo frene, puede codificarlos en el NOMBRE que consulta
(`ZGF0b3Mgcm9iYWRvcw.tunnel.atacante.com`) y leer la respuesta en un registro
TXT. Es lento, pero funciona, y es lo que usan varias familias de malware para
exfiltrar datos y para hablar con su servidor de control.

Lo importante para este proyecto: **esto solo lo puede ver un resolver.** El
proxy ve una conexión a un puerto; la VPN ve un túnel cifrado. El único que ve
los nombres consultados, uno por uno, es el DNS.

CÓMO SE DETECTA, Y POR QUÉ NINGUNA SEÑAL ALCANZA SOLA

Se agrupa por (equipo, dominio padre) y se miran cinco cosas. Cada una tiene
explicaciones inocentes, por eso hace falta que coincidan varias:

- **Muchos subdominios distintos.** Navegar normal repite nombres: entrás
  cinco veces a `www.google.com`. Un túnel casi nunca repite, porque cada
  consulta lleva datos diferentes. Sola no alcanza: un CDN también genera
  muchos nombres distintos.
- **Nombres largos.** Meter datos ocupa lugar, así que las etiquetas se van al
  máximo que permite el protocolo (63 caracteres). Sola no alcanza: hay
  servicios legítimos con nombres largos.
- **Alta entropía.** Los datos codificados en base32 o hexadecimal no se
  parecen a palabras. Sola no alcanza: los hashes y los identificadores de
  sesión tampoco.
- **Proporción alta de TXT o NULL.** Son los tipos que dejan devolver datos
  arbitrarios. Sola no alcanza: hay verificaciones de dominio y sistemas
  antispam que usan TXT.
- **Volumen sostenido contra un mismo padre.** Un túnel necesita muchas
  consultas para mover algo.

Por eso `evaluar_grupo` no devuelve "sí o no": devuelve **qué señales dieron**,
y hace falta un mínimo de señales coincidentes para marcar el grupo. El panel
muestra siempre cuáles fueron, para que se pueda discutir el hallazgo en vez de
tener que creerle.

ESTO SEÑALA, NO BLOQUEA

Misma decisión que los detectores por comportamiento de SecureProxy (ADR 0007
de ese proyecto). Un detector estadístico tiene falsos positivos, y un resolver
que corta por su cuenta te deja sin internet en base a una sospecha. Lo que
hace es marcarlo en el panel para que vos decidas.
"""

import math
from collections import Counter

# Sufijos de dos niveles bajo los que la gente registra dominios: en
# "ejemplo.com.ar" el dominio real es "ejemplo.com.ar" y no "com.ar". Sin esto,
# agrupar por "las dos últimas etiquetas" juntaría TODOS los sitios argentinos
# bajo un mismo padre y daría un falso positivo enorme.
#
# No es la lista pública de sufijos completa (esa tiene miles de entradas y es
# una dependencia externa que hay que mantener actualizada). Es la regla que
# cubre la enorme mayoría: un TLD de dos letras precedido de uno de estos.
SEGUNDOS_NIVELES = frozenset({
    "com", "net", "org", "gov", "edu", "mil", "int", "co", "ac", "gob", "or",
    "ne", "go", "web", "info", "tur", "nom",
})


def dominio_padre(nombre: str) -> str:
    """El dominio bajo el que se agrupa una consulta.

    "a3f9.tunel.atacante.com" -> "atacante.com"
    "www.ejemplo.com.ar"      -> "ejemplo.com.ar"

    La heurística: se toman las dos últimas etiquetas, y tres si la anteúltima
    es uno de los segundos niveles conocidos y el TLD tiene dos letras. Es una
    aproximación deliberada, no la lista pública de sufijos: alcanza para
    agrupar y no suma una dependencia externa que haya que mantener al día.
    """
    partes = [p for p in (nombre or "").strip().strip(".").lower().split(".") if p]
    if len(partes) <= 2:
        return ".".join(partes)
    if len(partes[-1]) == 2 and partes[-2] in SEGUNDOS_NIVELES and len(partes) >= 3:
        return ".".join(partes[-3:])
    return ".".join(partes[-2:])


def parte_variable(nombre: str, padre: str) -> str:
    """Lo que queda del nombre al sacarle el dominio padre.

    Es la parte que un túnel usa para llevar los datos, y por lo tanto la única
    que tiene sentido medir. Medir el nombre entero mezclaría la longitud del
    dominio del atacante con la de los datos, que es justo lo que se quiere
    separar.
    """
    nombre = (nombre or "").strip().strip(".").lower()
    padre = (padre or "").strip().strip(".").lower()
    if padre and nombre.endswith("." + padre):
        return nombre[: -(len(padre) + 1)]
    if nombre == padre:
        return ""
    return nombre


def entropia(texto: str) -> float:
    """Entropía de Shannon por carácter, en bits.

    Mide qué tan impredecible es el texto. Referencias útiles para leer el
    número: una palabra en castellano ronda los 3 bits por carácter, un
    identificador hexadecimal está cerca de 4, y algo en base32 o base64 pasa
    de 4,5. Los datos codificados de un túnel caen siempre en la parte alta,
    porque comprimidos o cifrados no tienen estructura de idioma.

    Se calcula sobre las letras del nombre sin los puntos: los separadores son
    del protocolo, no de los datos.
    """
    limpio = [c for c in (texto or "").lower() if c != "."]
    if not limpio:
        return 0.0
    total = len(limpio)
    return -sum(
        (cuenta / total) * math.log2(cuenta / total)
        for cuenta in Counter(limpio).values()
    )


# ---------------------------------------------------------------- umbrales
#
# Cada uno con su motivo. Están acá arriba y con nombre para que se puedan
# discutir y ajustar sin leer el código, que es la mitad del trabajo de un
# detector: los números elegidos son una decisión, no una verdad.

# Menos consultas que esto no es evidencia de nada: cualquier navegación
# genera un puñado de nombres distintos contra un mismo dominio.
MINIMO_DE_CONSULTAS = 40

# Qué proporción de las consultas al mismo padre son nombres distintos.
# Navegar repite; un túnel casi no repite, porque cada consulta lleva datos
# nuevos.
PROPORCION_DISTINTOS = 0.75

# Largo promedio de la parte variable. El protocolo permite 63 caracteres por
# etiqueta y un túnel tiende a llenarla; un subdominio normal ("www", "api",
# "cdn") no llega ni cerca.
LARGO_SOSPECHOSO = 25

# Bits por carácter. Por encima de esto el texto no se parece a palabras.
ENTROPIA_SOSPECHOSA = 3.6

# Proporción de consultas TXT o NULL. Son los tipos que permiten devolver
# datos arbitrarios, así que un túnel los usa mucho más que la navegación
# normal, donde son casi inexistentes.
PROPORCION_TXT = 0.30

# Cuántas señales tienen que coincidir para marcar el grupo. Con una sola hay
# demasiados falsos positivos (un CDN genera muchos nombres distintos, un hash
# tiene entropía alta); con tres se escapan túneles que van despacio.
SENALES_PARA_MARCAR = 2

TIPOS_DE_DATOS = ("TXT", "NULL")


def evaluar_grupo(grupo: dict) -> dict:
    """Evalúa un grupo (equipo + dominio padre) y devuelve qué señales dieron.

    `grupo` trae `total`, `distintos`, `tipos_de_datos`, `largo_promedio` y
    `entropia_promedio`. Devuelve el mismo diccionario con `senales` (lista de
    textos explicando cada una) y `sospechoso`.

    No devuelve un puntaje ni un "sí/no" pelado a propósito: lo que hace útil a
    un hallazgo es poder leer por qué se marcó y discutirlo.
    """
    resultado = dict(grupo)
    senales: list[str] = []

    total = int(grupo.get("total") or 0)
    if total < MINIMO_DE_CONSULTAS:
        resultado["senales"] = []
        resultado["sospechoso"] = False
        return resultado

    distintos = int(grupo.get("distintos") or 0)
    proporcion_distintos = distintos / total if total else 0.0
    if proporcion_distintos >= PROPORCION_DISTINTOS:
        senales.append(
            f"{distintos} nombres distintos sobre {total} consultas "
            f"({proporcion_distintos * 100:.0f}%): casi no repite, y navegar repite"
        )

    largo = float(grupo.get("largo_promedio") or 0.0)
    if largo >= LARGO_SOSPECHOSO:
        senales.append(
            f"los subdominios miden {largo:.0f} caracteres en promedio, "
            "mucho más que un www o un api"
        )

    ent = float(grupo.get("entropia_promedio") or 0.0)
    if ent >= ENTROPIA_SOSPECHOSA:
        senales.append(
            f"entropía de {ent:.2f} bits por carácter: no se parece a palabras"
        )

    tipos = int(grupo.get("tipos_de_datos") or 0)
    proporcion_tipos = tipos / total if total else 0.0
    if proporcion_tipos >= PROPORCION_TXT:
        senales.append(
            f"{proporcion_tipos * 100:.0f}% de las consultas son TXT o NULL, "
            "que son los tipos que dejan devolver datos arbitrarios"
        )

    resultado["senales"] = senales
    resultado["sospechoso"] = len(senales) >= SENALES_PARA_MARCAR
    return resultado


# --------------------------------------------------- actividad anómala

# Cuántas veces por encima de su propia línea de base tiene que estar un equipo
# para que valga la pena mirarlo. Tres es holgado: abrir una aplicación pesada
# duplica tranquilamente las consultas de una hora.
FACTOR_ANOMALIA = 3.0

# Horas de historia que hacen falta para tener una línea de base. Con dos o
# tres horas cualquier cosa parece un pico.
HORAS_DE_BASE = 6

# Piso absoluto: aunque un equipo pase de 2 consultas por hora a 40, veinte
# veces su base, cuarenta consultas no son una anomalía. Sin este piso el panel
# se llena de equipos que estaban apagados.
MINIMO_PARA_AVISAR = 200


def evaluar_actividad(cliente: str, ultima_hora: int, historia: list[int]) -> dict | None:
    """Compara la última hora de un equipo contra su propia historia.

    La comparación es contra sí mismo y no contra los demás equipos: una tele
    consulta muchísimo menos que una notebook, y un umbral fijo para todos
    marcaría siempre a la misma máquina. Lo que interesa es el cambio.

    Se usa la mediana y no el promedio: un solo pico previo arrastra el
    promedio hacia arriba y esconde el pico siguiente, que es justo lo que se
    quiere ver.
    """
    if len(historia) < HORAS_DE_BASE or ultima_hora < MINIMO_PARA_AVISAR:
        return None
    ordenada = sorted(historia)
    medio = len(ordenada) // 2
    if len(ordenada) % 2:
        base = float(ordenada[medio])
    else:
        base = (ordenada[medio - 1] + ordenada[medio]) / 2
    if base <= 0:
        return None
    factor = ultima_hora / base
    if factor < FACTOR_ANOMALIA:
        return None
    return {
        "cliente": cliente,
        "ultima_hora": ultima_hora,
        "base": base,
        "factor": factor,
    }
