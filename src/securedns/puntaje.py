"""Puntaje de seguridad del DNS de la red.

POR QUÉ ESTO ES PELIGROSO Y CÓMO SE HACE HONESTO

Un número grande arriba de un panel es lo más fácil de poner y lo más fácil de
que sea mentira. "97/100" tranquiliza, y si ese 97 sale de una fórmula que
nadie puede revisar, tranquiliza sin motivo. Eso es peor que no tener puntaje:
es dar seguridad falsa, que en una herramienta de seguridad es el peor
resultado posible.

Las tres reglas que lo hacen defendible, y que están puestas como tests:

1. **Cada punto que se resta sale de un hallazgo concreto.** No hay
   componentes "de ambiente" ni ponderaciones inventadas. Si el puntaje bajó,
   hay algo específico que lo bajó.
2. **Cada descuento es clickeable.** Al lado de "4 dominios recién
   registrados" hay un link que te lleva a esos 4. Un puntaje que no se puede
   auditar es un adorno.
3. **No se descuenta por cosas que no controlás.** El caso claro es DNSSEC: que
   la mitad de internet no firme sus dominios no es un problema de tu red, y
   restarte puntos por eso sería culparte de algo ajeno. Se muestra como dato,
   no como penalización.

POR QUÉ EMPIEZA EN 100 Y RESTA

Porque así el estado por defecto ("no encontré nada raro") es 100 y se
entiende solo. Sumando puntos habría que explicar por qué 63 es bueno o malo.
Restando, el número dice literalmente cuánto encontró.

QUÉ NO ES ESTE PUNTAJE

Es el puntaje del **DNS**, no de la red. Un 100 acá quiere decir que por el
resolver no pasó nada raro; no dice nada del tráfico que no pasa por DNS, ni
de las conexiones que ve SecureProxy, ni de si la VPN está levantada. El
puntaje de la red entera es de SecureCenter, que sí ve las tres capas.
"""

# Cuánto resta cada cosa, y por qué ese peso.
#
# La escala es intencionalmente gruesa: pesos de 5, 10, 15 y 20. Afinar esto a
# 7 o 13 puntos daría una precisión que los datos no tienen y volvería el
# número imposible de explicar.
PESOS = {
    # Lo más grave que puede encontrar este resolver: algo está sacando datos
    # de la red por un canal que casi nadie mira.
    "tunneling": 20,
    # Las consultas viajan en texto plano: cualquiera en el camino ve qué
    # dominios consultás. Es una decisión de configuración, no un ataque, pero
    # baja fuerte porque anula la razón de ser del proyecto.
    "sin_cifrado": 25,
    # Alguien pidió un dominio de malware o phishing. Que se haya bloqueado
    # está bien; que se haya pedido significa que hay algo en la red que lo
    # intentó.
    "amenaza_activa": 15,
    # Un equipo se salió de su ritmo. Puede ser una actualización, puede ser
    # otra cosa.
    "actividad_anomala": 10,
    # Las listas de amenazas están viejas: se está filtrando con información
    # de hace días.
    "listas_viejas": 15,
    # Un dominio de los hallazgos se registró hace poquito.
    "dominio_reciente": 10,
    # Si el cifrado falla se cae a texto plano. Es la opción razonable por
    # defecto, pero es una puerta abierta y conviene que se vea.
    "respaldo_sin_cifrar": 5,
}

# Techos por categoría: diez hallazgos de tunneling no pueden restar 200.
# Sin esto, el puntaje se clava en cero y deja de distinguir "un problema" de
# "un desastre", que es justo lo que tiene que distinguir.
TOPES = {
    "tunneling": 40,
    "actividad_anomala": 20,
    "amenaza_activa": 15,
    "dominio_reciente": 20,
}

# A partir de cuántas horas se considera que las listas están viejas. El ciclo
# normal es de 6 horas, así que 24 quiere decir que falló varias veces
# seguidas y no que se salteó una.
HORAS_LISTAS_VIEJAS = 24


def _nivel(puntaje: int) -> str:
    if puntaje >= 90:
        return "bien"
    if puntaje >= 70:
        return "atención"
    return "mal"


def calcular(estado: dict) -> dict:
    """Arma el puntaje a partir del estado que le pasa el panel.

    `estado` trae lo ya calculado por otros módulos: los hallazgos de
    detección, el modo de upstream, los bloqueos graves de las últimas 24
    horas, la antigüedad de las listas. Esta función no consulta nada: recibe
    y decide, así se puede probar entera sin base de datos ni red.

    Devuelve `{"puntaje", "nivel", "descuentos", "datos"}`. `descuentos` es la
    lista de lo que restó, cada uno con su texto, sus puntos y el link que
    lleva a verlo.
    """
    descuentos = []
    acumulado: dict[str, int] = {}

    def restar(clave: str, texto: str, enlace: str = "") -> None:
        peso = PESOS[clave]
        tope = TOPES.get(clave)
        ya = acumulado.get(clave, 0)
        if tope is not None:
            peso = max(0, min(peso, tope - ya))
        if peso <= 0:
            return
        acumulado[clave] = ya + peso
        descuentos.append({"texto": texto, "puntos": peso, "enlace": enlace, "clave": clave})

    # ---- transporte ----
    if estado.get("modo_upstream") != "dot":
        restar(
            "sin_cifrado",
            "Las consultas salen en texto plano: tu proveedor de internet puede "
            "ver qué dominios consultás.",
            "/?tab=config",
        )
    elif estado.get("respaldo_sin_cifrar"):
        restar(
            "respaldo_sin_cifrar",
            "Si el cifrado falla se cae a texto plano. Es lo razonable por "
            "defecto, pero es una puerta abierta.",
            "/?tab=config",
        )

    # ---- hallazgos de comportamiento ----
    for grupo in estado.get("tunneling") or []:
        restar(
            "tunneling",
            f"Posible tunneling por DNS: {grupo['padre']} desde {grupo['cliente']}.",
            f"/?q={grupo['padre']}",
        )
        if grupo.get("edad_reciente"):
            restar(
                "dominio_reciente",
                f"{grupo['padre']} se registró hace {grupo['edad_dias']} días, y "
                "los dominios nuevos son muy usados por malware.",
                f"/?q={grupo['padre']}",
            )

    for hallazgo in estado.get("actividad_anomala") or []:
        restar(
            "actividad_anomala",
            f"{hallazgo['cliente']} hizo {hallazgo['factor']:.1f} veces su ritmo "
            "habitual de consultas en la última hora.",
            f"/?cliente={hallazgo['cliente']}",
        )

    # ---- amenazas que alguien intentó ----
    for categoria, cantidad in (estado.get("amenazas_24h") or {}).items():
        if cantidad:
            restar(
                "amenaza_activa",
                f"Se bloquearon {cantidad} consultas de {categoria} en las últimas "
                "24 horas. Bloquearlas está bien; que se hayan pedido significa "
                "que hay algo en la red intentándolo.",
                f"/?cat={categoria}",
            )

    # ---- mantenimiento ----
    horas = estado.get("horas_desde_feeds")
    if horas is not None and horas >= HORAS_LISTAS_VIEJAS:
        restar(
            "listas_viejas",
            f"Las listas de amenazas se actualizaron hace {horas:.0f} horas: se "
            "está filtrando con información vieja.",
            "/?tab=config",
        )

    puntaje = max(0, 100 - sum(d["puntos"] for d in descuentos))
    return {
        "puntaje": puntaje,
        "nivel": _nivel(puntaje),
        "descuentos": descuentos,
        # Lo que se muestra como dato y NO descuenta, para que quede claro que
        # está mirado y que la decisión de no penalizarlo es deliberada.
        "informativo": estado.get("informativo") or {},
    }
