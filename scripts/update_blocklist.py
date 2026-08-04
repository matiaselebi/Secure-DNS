#!/usr/bin/env python3
"""Descarga feeds públicos de amenazas (URLhaus + OpenPhish) y genera
data/blocklist_feeds.txt con los dominios encontrados.

Se combina automáticamente con data/blocklist.txt (lista manual) cuando
corre el servidor DNS. Se puede correr manualmente (opción del menú, que
siempre fuerza la descarga), o dejar que scripts/run_dns.py lo haga solo al
arrancar, respetando un intervalo mínimo (filtering.feeds_update_interval_hours
en config/config.yaml) para no descargar de más.
"""

import os
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

URLHAUS_HOSTFILE = "https://urlhaus.abuse.ch/downloads/hostfile/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
OUTPUT_PATH = PROJECT_ROOT / "data" / "blocklist_feeds.txt"

# Feed opcional de dominios de publicidad/tracking (StevenBlack/hosts, formato
# "0.0.0.0 dominio" por línea). Es una categoría aparte y desactivada por
# defecto (filtering.enable_ad_tracker_blocklist: false en config.yaml):
# bloquear ads no es lo mismo que bloquear amenazas, y algunos sitios se
# rompen visualmente si dependen de un tracker para cargar contenido - se
# deja como opt-in explícito, no mezclado con la blocklist de seguridad.
AD_TRACKER_HOSTS_FEED = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
AD_TRACKER_OUTPUT_PATH = PROJECT_ROOT / "data" / "blocklist_adtracker.txt"


def fetch_ad_tracker_domains() -> set[str]:
    """Parsea el formato "0.0.0.0 dominio" (o "127.0.0.1 dominio") del feed
    de StevenBlack/hosts, ignorando localhost y comentarios."""
    domains: set[str] = set()
    try:
        response = requests.get(AD_TRACKER_HOSTS_FEED, timeout=20)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2:
                continue
            ip, hostname = parts[0], parts[1].lower()
            if ip not in ("0.0.0.0", "127.0.0.1"):
                continue
            if hostname in ("localhost", "localhost.localdomain", "local", "broadcasthost"):
                continue
            domains.add(hostname)
    except requests.RequestException as exc:
        print(f"[update_blocklist] No se pudo descargar el feed de ads/trackers: {exc}")
    return domains


def fetch_urlhaus_domains() -> set[str]:
    domains: set[str] = set()
    try:
        response = requests.get(URLHAUS_HOSTFILE, timeout=20)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) == 2:
                domains.add(parts[1].lower())
    except requests.RequestException as exc:
        print(f"[update_blocklist] No se pudo descargar URLhaus: {exc}")
    return domains


def fetch_openphish_domains() -> set[str]:
    domains: set[str] = set()
    try:
        response = requests.get(OPENPHISH_FEED, timeout=20)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            if not line:
                continue
            hostname = urlsplit(line).hostname
            if hostname:
                domains.add(hostname.lower())
    except requests.RequestException as exc:
        print(f"[update_blocklist] No se pudo descargar OpenPhish: {exc}")
    return domains


def escribir_atomico(destino: Path, contenido: str) -> None:
    """Escribe el archivo entero de una, o no lo escribe.

    Por qué importa acá: el resolver relee estas listas cada 15 segundos desde
    otro hilo. Abriendo el destino en modo "w" el archivo queda truncado
    mientras se escribe, así que una recarga que caiga justo en ese momento
    carga una lista A MEDIAS y filtra con ella hasta la recarga siguiente.
    Medido con el feed de publicidad: el resolver quedó con 109.163 de 150.000
    dominios cargados, o sea 15 segundos filtrando con dos tercios de la lista.

    Y si el proceso muere a mitad de la escritura, el archivo queda truncado
    para siempre: como `is_stale` mira la fecha de modificación, no se vuelve a
    descargar hasta seis horas después.

    Se escribe a un temporal en la MISMA carpeta (os.replace solo es atómico
    dentro del mismo sistema de archivos) y se renombra encima.
    """
    destino.parent.mkdir(parents=True, exist_ok=True)
    fd, temporal = tempfile.mkstemp(dir=str(destino.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(contenido)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporal, destino)
    except BaseException:
        try:
            os.unlink(temporal)
        except OSError:
            pass
        raise


def _bloque(categoria: str, dominios: set[str]) -> str:
    """Una sección con su marca de categoría adelante."""
    if not dominios:
        return ""
    return f"\n# categoria: {categoria}\n" + "".join(
        d + "\n" for d in sorted(dominios)
    )


def _escribir_bloque(f, categoria: str, dominios: set[str]) -> None:
    """Escribe una sección con su marca de categoría adelante."""
    if not dominios:
        return
    f.write(f"\n# categoria: {categoria}\n")
    for domain in sorted(dominios):
        f.write(domain + "\n")


def is_stale(path: Path, min_interval_hours: float) -> bool:
    if not path.exists():
        return True
    age_hours = (time.time() - path.stat().st_mtime) / 3600
    return age_hours >= min_interval_hours


def main(
    force: bool = False,
    min_interval_hours: float = 6,
    include_ad_tracker: bool = False,
) -> bool:
    if not force and not is_stale(OUTPUT_PATH, min_interval_hours):
        print(
            f"[update_blocklist] La lista se actualizó hace menos de "
            f"{min_interval_hours}h, se omite la descarga."
        )
        updated_security = False
    else:
        print("[update_blocklist] Descargando feeds de amenazas (URLhaus + OpenPhish)...")
        malware = fetch_urlhaus_domains()
        phishing = fetch_openphish_domains()
        # Un dominio puede estar en los dos feeds. Se queda en malware, que es
        # la categoría más grave: decir "phishing" de algo que URLhaus marcó
        # como malware sería quedarse corto. Y se saca de la otra lista para
        # que no aparezca dos veces.
        phishing -= malware
        domains = malware | phishing

        if not domains:
            print(
                "[update_blocklist] No se obtuvo ningún dominio (¿sin internet? "
                "¿los feeds están caídos?). No se modifica el archivo anterior."
            )
            updated_security = False
        else:
            escribir_atomico(OUTPUT_PATH,
                "# Generado automáticamente por scripts/update_blocklist.py\n"
                "# Fuentes: URLhaus (abuse.ch) + OpenPhish. NO editar a mano.\n"
                f"# Total de dominios: {len(domains)}\n"
                "#\n"
                "# Las lineas '# categoria: X' no son un comentario cualquiera:\n"
                "# el resolver las lee para saber de que es cada dominio, y asi\n"
                "# el panel puede decir 'malware' o 'phishing' en vez de un\n"
                "# generico 'bloqueado'. Ver src/securedns/blocklist.py.\n"
                + _bloque("malware", malware)
                + _bloque("phishing", phishing))
            print(
                f"[update_blocklist] Listo: {len(malware)} de malware y "
                f"{len(phishing)} de phishing guardados en {OUTPUT_PATH}"
            )
            updated_security = True

    updated_ad_tracker = False
    if include_ad_tracker:
        if not force and not is_stale(AD_TRACKER_OUTPUT_PATH, min_interval_hours):
            print(
                f"[update_blocklist] La lista de ads/trackers se actualizó hace menos "
                f"de {min_interval_hours}h, se omite la descarga."
            )
        else:
            print("[update_blocklist] Descargando feed de ads/trackers (StevenBlack/hosts)...")
            ad_tracker_domains = fetch_ad_tracker_domains()
            if ad_tracker_domains:
                escribir_atomico(AD_TRACKER_OUTPUT_PATH,
                    "# Generado automáticamente por scripts/update_blocklist.py\n"
                    "# Fuente: StevenBlack/hosts. NO editar a mano.\n"
                    f"# Total de dominios: {len(ad_tracker_domains)}\n"
                    + _bloque("publicidad", ad_tracker_domains))
                print(
                    f"[update_blocklist] Listo: {len(ad_tracker_domains)} dominios de "
                    f"ads/trackers guardados en {AD_TRACKER_OUTPUT_PATH}"
                )
                updated_ad_tracker = True
            else:
                print(
                    "[update_blocklist] No se obtuvo ningún dominio del feed de "
                    "ads/trackers. No se modifica el archivo anterior."
                )

    return updated_security or updated_ad_tracker


if __name__ == "__main__":
    updated = main(force=True, include_ad_tracker=True)
    if updated:
        print("[update_blocklist] El servidor DNS la recarga solo, no hace falta reiniciar.")
