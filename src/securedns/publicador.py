"""Dejarle a Pi-hole un archivo de listas y avisarle que lo tome.

QUÉ HACE, EN UNA LÍNEA

Agarra los dominios que juntó Secure-Intel, los escribe en el formato que
come `gravity`, se asegura de que Pi-hole tenga esa lista registrada, y le
pide que reconstruya. Nada más que eso, y a propósito.

POR QUÉ UN ARCHIVO LOCAL Y NO UNA URL

Pi-hole sabe tomar listas de un archivo con `file:///ruta`, igual que de una
URL. Publicar así evita levantar un servidor HTTP solo para que Pi-hole se
descargue algo que ya está en el mismo disco. La contra es real y hay que
decirla: **`file://` solo sirve si SecureDNS corre en la misma máquina que
Pi-hole**. Cuando no sea así, esa lista hay que servirla por HTTP, y lo único
que cambia es el `address` que se registra.

Un detalle de permisos que cuesta una tarde si no se sabe: `gravity` corre
como root cuando lo lanzás por consola, pero como el usuario `pihole` cuando
lo dispara el panel o la API, que es nuestro caso. Por eso el archivo se
escribe legible para todos (0644). Pi-hole aflojó ese requisito en su versión
nueva (PR 6430: alcanza con que el usuario que corre pueda leerlo), pero
0644 anda en las dos y no le cuesta nada a nadie.

LAS TRES GUARDAS, QUE SON EL VERDADERO CONTENIDO DE ESTE ARCHIVO

**No se publica una lista vacía.** Si Secure-Intel no tiene datos (base
recién creada, todas las fuentes caídas, un permiso mal puesto), publicar
cero dominios y correr gravity apaga el bloqueo entero sin un solo error en
pantalla. Se deja lo que ya estaba y se dice por qué.

**No se publica una lista que encogió de golpe.** Es la misma idea que ya usa
Secure-Intel al bajar un feed: si la lista nueva tiene menos de la mitad de
la anterior, casi seguro se rompió algo arriba. Se frena y se avisa. Este
caso es más grave acá que en cualquier otro lado, porque del otro lado hay un
Pi-hole que va a obedecer sin preguntar.

**No se corre gravity si el archivo no cambió.** Reconstruir el árbol con
millones de dominios cuesta minutos de CPU. Publicar cada seis horas cuando
los feeds cambiaron una vez por día sería gastarlos al pedo.
"""

import hashlib
import os
import tempfile
from pathlib import Path

from . import intel_puente

# Si la lista nueva tiene menos de esta fracción de la anterior, se frena.
# Mismo número que usa Secure-Intel para los feeds, por el mismo motivo.
FRACCION_MINIMA = 0.5

# Qué categorías de Secure-Intel se le publican a Pi-hole. La publicidad NO
# entra por defecto: Pi-hole ya viene con su propia lista de publicidad y
# duplicarla es hacerle procesar dos veces lo mismo. Lo nuestro es lo que
# Pi-hole no trae de fábrica.
CATEGORIAS = ("malware", "phishing")

ENCABEZADO = "# Generado por SecureDNS desde Secure-Intel. NO editar a mano."


def _lineas_de_dominios(dominios, nota: str) -> str:
    """El formato que come gravity: un dominio por línea, `#` es comentario.

    Se manda la lista pelada y no el formato hosts (`0.0.0.0 dominio`) porque
    gravity entiende los dos y este ocupa la mitad. Los comentarios de arriba
    los ignora, pero sirven para que cualquiera que abra el archivo en el
    servidor entienda de dónde salió y no lo edite.
    """
    limpios = sorted({d.strip().lower() for d in dominios if d and d.strip()})
    cabecera = [ENCABEZADO, f"# {nota}", f"# Total: {len(limpios)}", ""]
    return "\n".join(cabecera + limpios) + "\n"


def huella(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def _dominios_del_archivo(ruta: Path) -> set:
    """Los dominios de un archivo ya publicado, para poder compararlo.

    Se ignoran los comentarios, así que sirve tanto para un archivo nuestro
    como para uno escrito a mano.
    """
    dominios = set()
    try:
        with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
            for linea in f:
                limpia = linea.strip()
                if limpia and not limpia.startswith("#"):
                    dominios.add(limpia.split()[-1].lower())
    except OSError:
        return set()
    return dominios


def escribir_atomico(destino: Path, texto: str) -> None:
    """Temporal y `os.replace`, que es atómico.

    Pi-hole puede estar leyendo este archivo justo cuando lo reescribimos: si
    se abriera con `open(w)`, habría un instante en el que la lista está a
    medias, y si gravity la lee en ese instante bloquea de menos sin que nada
    falle. Es la misma técnica que usa Secure-Intel al exportar.
    """
    destino.parent.mkdir(parents=True, exist_ok=True)
    fd, temporal = tempfile.mkstemp(dir=str(destino.parent),
                                    prefix=destino.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(texto)
            f.flush()
            os.fsync(f.fileno())
        # Legible por el usuario `pihole`, que es el que corre gravity cuando
        # lo dispara la API. mkstemp crea con 0600, que no alcanza.
        os.chmod(temporal, 0o644)
        os.replace(temporal, destino)
    except BaseException:
        try:
            os.unlink(temporal)
        except OSError:
            pass
        raise


def dominios_a_publicar(cfg, categorias=CATEGORIAS) -> tuple[set, str]:
    """De dónde salen los dominios, en orden de preferencia.

    Primero Secure-Intel, que es el dueño de los feeds. Si no está instalado,
    se cae al archivo de texto que el resolutor ya venía leyendo: alguien que
    clonó solo SecureDNS igual puede publicar en su Pi-hole, sin obligarlo a
    clonar un tercer repositorio. Es la misma regla que ya sigue
    `intel_puente` para actualizar.
    """
    dominios = intel_puente.valores("dominio", categorias)
    if dominios:
        return dominios, "Secure-Intel"

    ruta = cfg.resolve_path(cfg.filtering.feeds_blocklist_path)
    del_archivo = _dominios_del_archivo(ruta)
    if del_archivo:
        return del_archivo, f"el archivo {ruta.name}"
    return set(), "ninguna fuente"


def publicar(cfg, cliente=None, forzar: bool = False) -> dict:
    """Todo el trabajo de la fase 1. Nunca lanza; devuelve un informe.

    El informe tiene siempre `ok` y `detalle`, y cuando corresponde `total`,
    `escribio` y `gravity`. Que sea un dict y no un booleano es para que el
    panel pueda mostrar por qué NO se publicó, que es el caso interesante.
    """
    conf = getattr(cfg, "pihole", None)
    if conf is None or not conf.habilitado:
        return {"ok": True, "detalle": "Pi-hole desactivado en el config", "salteado": True}

    carpeta = Path(conf.carpeta_listas)
    destino = carpeta / conf.nombre_lista

    dominios, origen = dominios_a_publicar(cfg)
    if not dominios:
        # Vacío nunca se publica. Ver el comentario de arriba: es la guarda
        # que evita apagar el bloqueo de toda la casa sin un solo error.
        return {"ok": False, "total": 0, "escribio": False,
                "detalle": ("no hay ni un dominio para publicar (¿Secure-Intel "
                            "nunca bajó nada?). Dejo la lista como estaba")}

    previos = _dominios_del_archivo(destino)
    if previos and len(dominios) < len(previos) * FRACCION_MINIMA and not forzar:
        return {"ok": False, "total": len(dominios), "escribio": False,
                "detalle": (f"la lista nueva tiene {len(dominios)} dominios y la "
                            f"anterior tenía {len(previos)}: encogió demasiado, no "
                            f"la publico. Revisá {origen} y volvé a intentar")}

    texto = _lineas_de_dominios(dominios, f"origen: {origen}")
    cambio = huella(texto) != huella_actual(destino)
    if cambio:
        try:
            escribir_atomico(destino, texto)
        except OSError as exc:
            return {"ok": False, "total": len(dominios), "escribio": False,
                    "detalle": (f"no pude escribir {destino}: {exc}. ¿Existe la "
                                f"carpeta y tenés permiso? (probá con sudo o "
                                f"creála con el dueño correcto)")}

    informe = {"ok": True, "total": len(dominios), "escribio": cambio,
               "origen": origen, "archivo": str(destino)}

    if cliente is None:
        informe["detalle"] = (f"{len(dominios)} dominios en {destino} "
                              f"({'actualizado' if cambio else 'sin cambios'}); "
                              f"no le avisé a Pi-hole (sin cliente)")
        return informe

    address = conf.address or f"file://{destino}"
    ok_lista, detalle_lista = cliente.asegurar_lista(address, conf.comentario)
    informe["lista"] = detalle_lista
    if not ok_lista:
        informe["ok"] = False
        informe["detalle"] = f"escribí la lista pero Pi-hole no la tomó: {detalle_lista}"
        return informe

    # gravity solo si algo cambió. Si la lista es la misma, reconstruir el
    # árbol entero no cambia nada y cuesta minutos.
    if not cambio and not forzar:
        informe["gravity"] = "no hizo falta (la lista no cambió)"
        informe["detalle"] = f"{len(dominios)} dominios, sin cambios desde la última vez"
        return informe

    if not conf.correr_gravity:
        informe["gravity"] = "desactivado en el config"
        informe["detalle"] = (f"{len(dominios)} dominios publicados; gravity queda "
                              f"para vos (correr_gravity: false)")
        return informe

    ok_gravity, detalle_gravity = cliente.gravity()
    informe["gravity"] = detalle_gravity
    informe["ok"] = ok_gravity
    informe["detalle"] = (f"{len(dominios)} dominios publicados y gravity corrido"
                          if ok_gravity else
                          f"publiqué {len(dominios)} dominios pero gravity falló: "
                          f"{detalle_gravity}")
    return informe


def huella_actual(destino: Path) -> str:
    """La huella del archivo que ya está publicado, o vacío si no hay."""
    try:
        return huella(Path(destino).read_text(encoding="utf-8"))
    except OSError:
        return ""
