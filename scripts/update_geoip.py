#!/usr/bin/env python3
"""Descarga e importa la base de país y ASN por IP (DB-IP lite, gratuita).

Se corre a mano o desde el menú del .bat, y con una vez por mes alcanza: las
asignaciones de red no cambian todos los días. El proxy NO la descarga solo
durante el tráfico, a propósito, porque son varios megabytes.

Formato de origen: CSV de rangos (`ip_inicio,ip_fin,valor`), comprimido en
gzip. Se importa a SQLite convirtiendo cada rango a un par de enteros, que es
lo que permite después resolver una IP con una búsqueda por índice en vez de
recorriendo (ver src/securedns/geoip.py).

Uso:
    python scripts/update_geoip.py            # descarga e importa
    python scripts/update_geoip.py archivo.csv  # importa un CSV ya bajado
"""

import csv
import gzip
import io
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import sqlite3  # noqa: E402

import requests  # noqa: E402

from securedns import http_client  # noqa: E402
from securedns.geoip import ip_a_entero  # noqa: E402

DB_PATH = PROJECT_ROOT / "data" / "geoip.db"

# DB-IP publica sus bases "lite" gratis y sin cuenta, una por mes, bajo
# licencia CC-BY. Se arma la URL con el mes en curso y, si todavía no está
# publicada, se prueba con el mes anterior.
PLANTILLA_PAIS = "https://download.db-ip.com/free/dbip-country-lite-{aa}-{mm}.csv.gz"
PLANTILLA_ASN = "https://download.db-ip.com/free/dbip-asn-lite-{aa}-{mm}.csv.gz"


def _meses_a_probar() -> list[tuple[int, int]]:
    hoy = datetime.now(timezone.utc)
    anterior_mes = hoy.month - 1 or 12
    anterior_anio = hoy.year if hoy.month > 1 else hoy.year - 1
    return [(hoy.year, hoy.month), (anterior_anio, anterior_mes)]


# Tope de lo que se acepta descomprimido. Un .gz de pocos megas puede
# expandirse a gigabytes (una "bomba de descompresión"), y acá se decodifica
# entero en memoria: sin tope, la descarga podía voltear la máquina.
MAX_DESCOMPRIMIDO = 512 * 1024 * 1024


def _descomprimir_con_tope(datos: bytes) -> str:
    """Descomprime de a pedazos y corta si se pasa del tope."""
    descompresor = gzip.GzipFile(fileobj=io.BytesIO(datos))
    partes = []
    total = 0
    while True:
        pedazo = descompresor.read(4 * 1024 * 1024)
        if not pedazo:
            break
        total += len(pedazo)
        if total > MAX_DESCOMPRIMIDO:
            raise OSError(
                f"el archivo descomprimido supera {MAX_DESCOMPRIMIDO // (1024 * 1024)} MB"
            )
        partes.append(pedazo)
    return b"".join(partes).decode("utf-8", errors="replace")


def descargar(plantilla: str) -> str | None:
    """Baja el CSV comprimido del mes más reciente que exista."""
    for anio, mes in _meses_a_probar():
        url = plantilla.format(aa=anio, mm=f"{mes:02d}")
        print(f"[update_geoip] probando {url}")
        try:
            respuesta = http_client.get(url, timeout=120)
            if respuesta.status_code == 404:
                continue
            respuesta.raise_for_status()
            return _descomprimir_con_tope(respuesta.content)
        except (requests.RequestException, OSError, EOFError) as exc:
            print(f"[update_geoip] no se pudo: {exc}")
    return None


def importar(texto_pais: str, texto_asn: str, db_path: Path) -> int:
    """Arma la base local. Devuelve cuántos rangos quedaron.

    Los dos CSV se cruzan por rango: el de países da el país, el de ASN da el
    número de sistema autónomo y el nombre del proveedor. Se guarda una fila
    por rango del CSV de países, completada con el ASN que le corresponda.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    # Se arma en un archivo temporal y recién al final se reemplaza la base
    # buena. Antes se borraba la vieja ANTES de saber si el CSV servía: con
    # un archivo vacío o con basura te quedabas sin la base anterior y con
    # una nueva inútil.
    temporal = db_path.with_suffix(".db.tmp")
    if temporal.exists():
        temporal.unlink()

    conn = sqlite3.connect(str(temporal))
    conn.execute(
        "CREATE TABLE rangos (inicio INTEGER NOT NULL, fin INTEGER NOT NULL, "
        "pais TEXT, asn TEXT, proveedor TEXT)"
    )

    # Los ASN se cargan primero en memoria como lista ordenada de rangos,
    # para poder buscarlos por bisección al recorrer los países.
    import bisect

    asn_inicios: list[int] = []
    asn_datos: list[tuple[int, str, str]] = []
    for fila in csv.reader(io.StringIO(texto_asn)):
        if len(fila) < 4:
            continue
        inicio, fin = ip_a_entero(fila[0]), ip_a_entero(fila[1])
        if inicio is None or fin is None:
            continue
        asn_inicios.append(inicio)
        asn_datos.append((fin, fila[2], fila[3]))
    orden = sorted(range(len(asn_inicios)), key=lambda i: asn_inicios[i])
    asn_inicios = [asn_inicios[i] for i in orden]
    asn_datos = [asn_datos[i] for i in orden]

    def asn_de(valor: int) -> tuple[str, str]:
        indice = bisect.bisect_right(asn_inicios, valor) - 1
        if indice < 0:
            return "", ""
        fin, numero, nombre = asn_datos[indice]
        if valor > fin:
            return "", ""
        return numero, nombre

    filas = []
    for fila in csv.reader(io.StringIO(texto_pais)):
        if len(fila) < 3:
            continue
        inicio, fin = ip_a_entero(fila[0]), ip_a_entero(fila[1])
        if inicio is None or fin is None:
            continue
        numero, proveedor = asn_de(inicio)
        filas.append((inicio, fin, fila[2], numero, proveedor))
        if len(filas) >= 20_000:
            conn.executemany("INSERT INTO rangos VALUES (?,?,?,?,?)", filas)
            filas.clear()
    if filas:
        conn.executemany("INSERT INTO rangos VALUES (?,?,?,?,?)", filas)

    conn.execute("CREATE INDEX idx_rangos_inicio ON rangos (inicio)")
    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM rangos").fetchone()[0]
    conn.close()

    if total == 0:
        # No sirvió: se deja la base anterior donde estaba.
        temporal.unlink()
        raise ValueError(
            "el CSV no trajo ningún rango usable; se deja la base anterior intacta"
        )
    os.replace(temporal, db_path)
    return total


def main() -> int:
    if len(sys.argv) > 1:
        texto_pais = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
        texto_asn = ""
        if len(sys.argv) > 2:
            texto_asn = Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace")
    else:
        print("[update_geoip] Descargando la base de países...")
        texto_pais = descargar(PLANTILLA_PAIS)
        if texto_pais is None:
            print("[update_geoip] ERROR: no se pudo descargar la base de países.")
            return 1
        print("[update_geoip] Descargando la base de ASN...")
        texto_asn = descargar(PLANTILLA_ASN) or ""
        if not texto_asn:
            print("[update_geoip] AVISO: sin base de ASN; solo va a haber país.")

    print("[update_geoip] Importando (tarda un momento)...")
    try:
        total = importar(texto_pais, texto_asn, DB_PATH)
    except ValueError as exc:
        print(f"[update_geoip] ERROR: {exc}")
        return 1
    print(f"[update_geoip] Listo: {total:,} rangos en {DB_PATH}".replace(",", "."))
    print("[update_geoip] Reiniciá el resolver para que la empiece a usar.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
