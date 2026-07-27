"""Validación básica de formato de dominio para los formularios del
dashboard y las opciones del menú .bat que agregan a la allowlist/blocklist.

No es una validación exhaustiva de RFC 1035 (no hace falta: si alguien
escribe algo raro a mano, el objetivo es solo evitar basura obvia en los
archivos de listas - espacios, cadenas vacías, protocolos/paths pegados
por error al copiar una URL - no blindar contra un input adversarial,
porque estos formularios ya son de uso exclusivamente local)."""

import ipaddress
import re

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.[a-zA-Z]{2,63}$"
)


def is_valid_domain(domain: str) -> bool:
    """True si `domain` tiene forma de nombre de dominio (letras/números/
    guiones separados por puntos, con un TLD alfabético al final) o de
    dirección IPv4/IPv6 literal (el proxy también puede filtrar por IP
    directa, no solo por nombre). Rechaza cadenas vacías, con espacios, con
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
