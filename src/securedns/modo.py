"""Quién resuelve: el resolutor propio o Pi-hole.

POR QUÉ ESTO ES UNA PIEZA Y NO UN `if` SUELTO

Porque la respuesta a "quién resuelve" cambia el comportamiento de cinco
lugares distintos: si se abre el puerto 53, si se toca el DNS del sistema, qué
muestra el panel, qué hilos se levantan, y qué le dice SecureCenter al
adaptador de red. Con un `if` en cada uno, alcanza con olvidarse de uno para
tener la peor falla posible de todas: **el sistema apuntando a un resolutor
que no está escuchando**, que es quedarse sin internet sin ningún mensaje de
error. Ya pasó una vez en este proyecto por una duplicación parecida.

Acá se contesta una sola vez y todos preguntan lo mismo.

LOS TRES MODOS

- `propio`: SecureDNS resuelve, como siempre. Abre el 53, habla DoT, cachea.
- `pihole`: resuelve Pi-hole. SecureDNS **no** abre el 53 y **no** toca el DNS
  del sistema; publica listas, importa consultas y analiza.
- `auto` (el de fábrica): `pihole` si Pi-hole está habilitado, `propio` si no.
  Es lo que hace que nadie tenga que tocar dos claves para lo mismo, y que
  quien nunca configuró Pi-hole siga teniendo el comportamiento de siempre.

LA CONTRADICCIÓN QUE SE ATAJA ACÁ

`modo: "pihole"` con `pihole.habilitado: false` es pedir que resuelva alguien
que no está configurado. Si se obedeciera al pie de la letra, no resolvería
nadie. Se avisa fuerte y se vuelve a `propio`, que es el único de los dos que
puede funcionar solo. Fallar hacia el lado que sigue resolviendo nombres.
"""

AUTO, PROPIO, PIHOLE = "auto", "propio", "pihole"
MODOS = (AUTO, PROPIO, PIHOLE)


def resolutor_activo(cfg, avisar=print) -> str:
    """`propio` o `pihole`. Nunca devuelve `auto`: acá se decide."""
    pedido = str(getattr(cfg.dns, "modo", AUTO) or AUTO).strip().lower()
    pihole_listo = bool(getattr(getattr(cfg, "pihole", None), "habilitado", False))

    if pedido not in MODOS:
        avisar(f"[SecureDNS] modo '{pedido}' desconocido; uso 'auto'")
        pedido = AUTO

    if pedido == AUTO:
        return PIHOLE if pihole_listo else PROPIO

    if pedido == PIHOLE and not pihole_listo:
        avisar("[SecureDNS] AVISO: dns.modo dice 'pihole' pero pihole.habilitado "
               "está en false. Nadie resolvería. Sigo con el resolutor propio; "
               "arreglá una de las dos claves.")
        return PROPIO

    return pedido


def resuelve_pihole(cfg, avisar=print) -> bool:
    return resolutor_activo(cfg, avisar) == PIHOLE


def toca_el_dns_del_sistema(cfg, avisar=print) -> bool:
    """¿Corresponde apuntar el adaptador de red a 127.0.0.1?

    Solo en modo propio. En modo Pi-hole el que tiene que estar en el
    adaptador es Pi-hole, y apuntar a 127.0.0.1 dejaría a la máquina hablando
    con un puerto donde no escucha nadie.
    """
    return not resuelve_pihole(cfg, avisar)


class ResolutorJubilado:
    """Un resolutor que no resuelve, para cuando resuelve Pi-hole.

    El panel le pregunta dos cosas al resolutor: cuántas entradas tiene el
    caché y que lo vacíe. En modo Pi-hole no hay caché propio, así que la
    alternativa sería llenar el panel de `if resolver is not None`. Este
    objeto contesta lo que corresponde y el panel no se entera.

    Contesta 0 y no un número inventado, y `clear_cache` no hace nada en vez
    de fingir que vació algo. Un panel que dice "caché: 1.240" cuando no hay
    caché es exactamente la clase de mentira que la regla 10 prohíbe.
    """

    jubilado = True

    def cache_size(self) -> int:
        return 0

    def clear_cache(self) -> None:
        return None


def descripcion(cfg, avisar=lambda *_: None) -> dict:
    """Qué contar en el panel y en la consola sobre quién resuelve.

    `no_aplica` es la lista de cosas que existen en el código y NO están
    funcionando en este modo. Decirlo es la mitad del trabajo: un panel que
    sigue mostrando "upstream: Quad9 por DoT" cuando el que resuelve es
    Pi-hole está describiendo un resolutor apagado.
    """
    activo = resolutor_activo(cfg, avisar)
    if activo == PIHOLE:
        return {
            "modo": PIHOLE,
            "quien_resuelve": "Pi-hole",
            "titulo": "Resuelve Pi-hole; SecureDNS analiza",
            "detalle": ("SecureDNS no está escuchando en el puerto 53 ni tocando "
                        "el DNS del sistema. Le publica las listas a Pi-hole, le "
                        "importa las consultas y les corre encima la detección."),
            "no_aplica": ["caché propio", "upstream y DNS-over-TLS",
                          "modo de bloqueo (lo decide Pi-hole)",
                          "DNS del sistema"],
        }
    return {
        "modo": PROPIO,
        "quien_resuelve": "SecureDNS",
        "titulo": "Resuelve SecureDNS",
        "detalle": "SecureDNS escucha en el puerto 53 y resuelve por su cuenta.",
        "no_aplica": [],
    }
