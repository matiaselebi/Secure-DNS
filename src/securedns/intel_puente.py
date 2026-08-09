"""Si Secure-Intel está instalado al lado, que baje él los feeds.

EL PROBLEMA QUE ESTO ARREGLA

La URL de URLhaus estaba escrita en dos lugares: acá y en SecureProxy. Igual
OpenPhish, e igual las dos bases de db-ip. El día que abuse.ch cambie una URL,
arreglás uno, verificás que anda, y el otro se queda bajando un 404 en
silencio: el archivo viejo sigue ahí, el panel sigue diciendo que hay 40.000
reglas, y nadie se entera hasta que pasa algo.

Secure-Intel es el único lugar donde vive esa URL ahora.

POR QUÉ EL MOTOR DE FILTRADO NO CAMBIA UNA LÍNEA

Porque anda, está probado, y está en el camino de cada conexión. Secure-Intel
escribe los MISMOS archivos de texto que el resolutor ya leía, en el mismo
formato y en el mismo lugar. Lo único que cambia es de dónde salieron esos
bytes. Cambiar además el motor sería correr un riesgo que esta migración no
necesita correr para cumplir su objetivo.

SI SECURE-INTEL NO ESTÁ

No pasa nada: se sigue bajando como siempre, con el código de
`scripts/update_blocklist.py` que quedó intacto. Nadie está obligado a clonar
un tercer repositorio para que el DNS funcione.
"""

import sys
from pathlib import Path

# Dónde puede estar clonado. Se busca entre las carpetas hermanas, igual que
# hace SecureHIPS con la base de GeoIP y SecureCenter con los proyectos.
CARPETAS = ("secure-intel", "Secure-Intel", "secureintel")


def buscar(raiz=None) -> Path | None:
    """La carpeta de Secure-Intel, o None si no está instalado."""
    if raiz is None:
        raiz = Path(__file__).resolve().parent.parent.parent.parent
    for nombre in CARPETAS:
        candidata = Path(raiz) / nombre
        if (candidata / "src" / "secureintel").is_dir():
            return candidata
    return None


def disponible(raiz=None) -> bool:
    return buscar(raiz) is not None


def actualizar(forzar: bool = False, raiz=None,
               incluir_opcionales: bool | None = None) -> bool:
    """Le pide a Secure-Intel que baje y exporte. True si se hizo.

    Nunca lanza. Si algo sale mal se avisa y se devuelve False, para que el
    que llama caiga en el camino de siempre. Un tercer repositorio con un
    problema no puede dejar al DNS sin listas.
    """
    carpeta = buscar(raiz)
    if carpeta is None:
        return False
    ruta_src = str(carpeta / "src")
    if ruta_src not in sys.path:
        sys.path.insert(0, ruta_src)
    try:
        from secureintel.actualizador import actualizar as correr
        from secureintel.config_loader import load_config

        cfg = load_config(str(carpeta / "config" / "config.yaml"))
        # SecureDNS decide por su cuenta si bloquea publicidad, así que puede
        # pedirle a Secure-Intel que baje también esa lista. `None` deja lo
        # que diga el config de Secure-Intel.
        if incluir_opcionales is not None:
            cfg.fuentes.incluir_opcionales = bool(incluir_opcionales)
        # La base y las exportaciones son de Secure-Intel: sus rutas se
        # resuelven contra SU carpeta, no contra la del DNS.
        resumen = correr(cfg, forzar=forzar)
    except Exception as exc:  # noqa: BLE001
        print(f"[SecureDNS] Secure-Intel está pero no pude usarlo ({exc}); "
              "bajo los feeds como antes")
        return False
    if not resumen:
        return False
    fallaron = [n for n, d in resumen.items() if not d.get("ok")]
    if len(fallaron) == len(resumen):
        # No pudo con NINGUNA. Devolver True acá sería lo peor: el que llama
        # daría la actualización por hecha y ni siquiera intentaría por su
        # cuenta. Sin internet, con las dos rutas cortadas, nadie actualiza
        # nada y el panel no se entera.
        print(f"[SecureDNS] Secure-Intel no pudo bajar ninguna fuente; "
              "sigo por el camino de siempre")
        return False
    if fallaron:
        print(f"[SecureDNS] Secure-Intel: no pudo con {', '.join(fallaron)} "
              "(se dejaron los datos anteriores)")
    return True
