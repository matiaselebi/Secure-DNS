"""Escritura quirúrgica del config.yaml, preservando comentarios.

Por qué no se usa `yaml.dump`: PyYAML puede leer el archivo, pero al
volver a escribirlo **borra todos los comentarios** y reordena las claves.
Los config.yaml de estos proyectos están llenos de comentarios que explican
cada opción -son parte del valor del proyecto- así que perderlos por cambiar
un booleano desde el dashboard sería un mal negocio.

La estrategia: buscar la línea exacta de esa clave dentro de su sección y
reemplazar SOLO el valor, dejando intactos la indentación, el comentario al
final de la línea y todo el resto del archivo.
"""

import re
from pathlib import Path


def format_value(value) -> str:
    """Convierte un valor de Python a su forma YAML."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return f'"{value}"'


def set_value(config_path: str | Path, section: str, key: str, value) -> bool:
    """Cambia `section.key` a `value` en el archivo, preservando el resto.

    Devuelve True si encontró la clave y la cambió. No crea claves nuevas a
    propósito: si la clave no existe, es que algo no cuadra (¿otro archivo?
    ¿otra versión?) y es mejor avisar que escribir a ciegas.
    """
    path = Path(config_path)
    if not path.exists():
        return False

    lineas = path.read_text(encoding="utf-8").splitlines(keepends=True)
    dentro_de_seccion = False
    patron_clave = re.compile(rf"^(\s+){re.escape(key)}:\s*(.*?)(\s*#.*)?(\r?\n|$)")

    for i, linea in enumerate(lineas):
        # Inicio de una sección de primer nivel (sin indentación).
        if re.match(r"^\S", linea):
            dentro_de_seccion = linea.split(":")[0].strip() == section
            continue
        if not dentro_de_seccion:
            continue
        match = patron_clave.match(linea)
        if match:
            indent, _viejo, comentario, salto = match.groups()
            comentario = comentario or ""
            salto = salto or "\n"
            lineas[i] = f"{indent}{key}: {format_value(value)}{comentario}{salto}"
            path.write_text("".join(lineas), encoding="utf-8")
            return True

    return False


def read_value(config_path: str | Path, section: str, key: str, default=None):
    """Lee un valor puntual sin cargar todo el config (para confirmar que un
    cambio quedó escrito)."""
    import yaml

    path = Path(config_path)
    if not path.exists():
        return default
    datos = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return datos.get(section, {}).get(key, default)
