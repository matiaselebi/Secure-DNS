"""Validación y normalización de dominios para los formularios del dashboard
y las opciones del menú .bat que agregan a la allowlist/blocklist.

No es una validación exhaustiva de RFC 1035 (no hace falta: si alguien
escribe algo raro a mano, el objetivo es solo evitar basura obvia en los
archivos de listas - espacios, cadenas vacías, protocolos/paths pegados
por error al copiar una URL - no blindar contra un input adversarial,
porque estos formularios ya son de uso exclusivamente local).

Es el mismo módulo que en SecureProxy, con una diferencia deliberada: acá el
`www.` NO se saca de lo que se MUESTRA, porque en DNS `www.ejemplo.com` y
`ejemplo.com` son dos nombres distintos. Ver `limpiar_para_mostrar`.
"""

import ipaddress
import re

_ESQUEMA_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://")

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.[a-zA-Z]{2,63}$"
)


def normalizar_dominio(texto: str) -> tuple[str, list[str]]:
    """Convierte lo que sea que hayan pegado en un dominio limpio.

    Nadie copia dominios: uno copia la barra del navegador, y de ahí sale
    "https://www.ejemplo.com/algo?x=1". Antes eso se rechazaba en silencio
    (el formulario validaba, no pasaba la validación, y no guardaba nada sin
    decir por qué) y había que editarlo a mano, que es exactamente el momento
    en que uno se equivoca.

    Devuelve `(dominio, avisos)`. Los avisos explican qué se le sacó, para
    poder mostrárselo en pantalla: una lista de bloqueo que calladamente
    guarda algo distinto de lo que escribiste es una fuente de sorpresas.

    Lo que saca, y por qué:

    - **El esquema** (`https://`): un resolver no sabe de protocolos, solo
      de nombres.
    - **El camino** (`/algo`): el DNS resuelve nombres, no URLs. Nunca ve el
      camino, así que una regla con camino no podría aplicarse jamás. Se
      bloquea el nombre entero y se avisa.
    - **El puerto** (`:8443`): igual, el resolver no lo ve.
    - **El `www.`**: las listas ya matchean subdominios, así que guardando
      `ejemplo.com` la regla cubre también `www.ejemplo.com`. Al revés no:
      guardar `www.ejemplo.com` dejaría pasar el dominio raíz.
    """
    avisos: list[str] = []
    dominio = (texto or "").strip().lower()
    if not dominio:
        return "", avisos

    if _ESQUEMA_RE.match(dominio):
        dominio = _ESQUEMA_RE.sub("", dominio, count=1)
        avisos.append("se sacó el http/https")

    # Credenciales pegadas en la URL (usuario:clave@host). Raro, pero si
    # aparece hay que quedarse con el host, no con el usuario.
    if "@" in dominio:
        dominio = dominio.rsplit("@", 1)[1]

    for corte in ("/", "?", "#"):
        if corte in dominio:
            resto = dominio.split(corte, 1)[1]
            dominio = dominio.split(corte, 1)[0]
            if corte == "/" and resto:
                avisos.append(
                    "se sacó el camino después de la barra: el DNS resuelve "
                    "nombres, no URLs, así que la regla cubre el sitio entero"
                )

    # Puerto. Ojo con IPv6 entre corchetes, que lleva ":" adentro.
    if not dominio.startswith("[") and dominio.count(":") == 1:
        cabeza, _, cola = dominio.partition(":")
        if cola.isdigit():
            dominio = cabeza
            avisos.append("se sacó el puerto")

    dominio = dominio.strip(".")

    if dominio.startswith("www.") and len(dominio) > 4:
        dominio = dominio[4:]
        avisos.append("se sacó el www. (la regla cubre igual www. y sin www.)")

    return dominio, avisos


def limpiar_para_mostrar(dominio: str) -> str:
    """El nombre como conviene LEERLO en una tabla.

    Ojo con la diferencia respecto de SecureProxy: acá NO se saca el `www.`.
    En el proxy se puede, porque lo que se muestra es a qué sitio fuiste y
    `www.ejemplo.com` y `ejemplo.com` son el mismo sitio. En un resolver son
    dos NOMBRES distintos, que pueden apuntar a IPs distintas; taparlo haría
    que dos filas legítimamente diferentes se vean idénticas, justo lo
    contrario de lo que uno quiere mirando un log de DNS.

    Lo único que se saca es el punto final del FQDN (`ejemplo.com.`), que es
    notación y no información.
    """
    return (dominio or "").strip().strip(".")


def normalizar_nombre_consultado(dominio: str) -> str:
    """El nombre tal como hay que compararlo contra las listas.

    Existe por un bypass de un solo carácter. El DNS trata "nanopool.org."
    (con punto final, la forma absoluta de un FQDN) y "nanopool.org" como el
    mismo nombre; pero las listas comparan texto, así que con el punto al
    final no matcheaba nada y la consulta pasaba limpita. Pasaba igual con
    los nombres internacionales, que se comparaban en Unicode mientras los
    feeds los publican en punycode.
    """
    limpio = (dominio or "").strip().strip(".").lower()
    if not limpio:
        return ""
    try:
        # IDNA deja los nombres internacionales en la misma forma en que los
        # publican los feeds. Si falla (etiqueta demasiado larga, caracteres
        # raros) se devuelve lo que había: es preferible comparar algo
        # imperfecto a no comparar nada.
        return limpio.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError, ValueError):
        return limpio


def is_valid_domain(domain: str) -> bool:
    """True si `domain` tiene forma de nombre de dominio (letras/números/
    guiones separados por puntos, con un TLD alfabético al final) o de
    dirección IPv4/IPv6 literal. Rechaza cadenas vacías, con espacios, con
    "http://" o rutas pegadas, o con caracteres fuera de lo esperado."""
    domain = domain.strip().lower()
    if not domain or " " in domain:
        return False
    if "/" in domain:
        return False
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        pass
    if ":" in domain:
        return False
    return bool(_DOMAIN_RE.match(domain))
