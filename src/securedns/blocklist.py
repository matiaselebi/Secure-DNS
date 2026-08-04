"""Lista negra de dominios, cargada desde uno o varios archivos de texto.

Además de decir SI un dominio está bloqueado, dice POR QUÉ CATEGORÍA. Eso no
es un adorno del panel: "se bloquearon 143 consultas" no dice nada, mientras
que "12 de malware, 3 de phishing, 128 de publicidad" dice si tenés un
problema o si simplemente estás filtrando anuncios.

La categoría NO se inventa: sale de en qué feed apareció el dominio. Los
archivos generados llevan marcas `# categoria: malware` antes de cada bloque
(las escribe scripts/update_blocklist.py), y todo lo que no tenga marca cae en
la categoría por defecto del archivo. Un archivo viejo, de antes de que las
marcas existieran, sigue funcionando: queda como "amenaza" a secas.
"""

from pathlib import Path

from .validation import normalizar_nombre_consultado

# Prefijo de las marcas de categoría dentro de un archivo de lista.
MARCA_CATEGORIA = "# categoria:"

# Categorías conocidas y cómo se llaman en el panel. Es una lista cerrada a
# propósito: si un feed nuevo trae una categoría que no está acá, se muestra
# tal cual vino en vez de inventarle un nombre lindo.
NOMBRES_DE_CATEGORIA = {
    "malware": "Malware",
    "phishing": "Phishing",
    "publicidad": "Publicidad y rastreadores",
    "mineria": "Minería de cripto",
    "manual": "Lista manual",
    "amenaza": "Amenaza (sin clasificar)",
}


def nombre_de_categoria(clave: str) -> str:
    return NOMBRES_DE_CATEGORIA.get(clave, clave or "sin categoría")


class Blocklist:
    """Combina una lista curada a mano con una generada automáticamente
    (feeds de amenazas), sin que se pisen entre sí."""

    def __init__(self, path: str | list[str], categoria_por_defecto: str = "manual"):
        if isinstance(path, str):
            path = [path]
        self.paths = [Path(p) for p in path]
        # La categoría que se le asigna a lo que no trae marca. El primer
        # archivo es siempre el manual; del segundo en adelante son generados,
        # y si no dicen de qué son, lo honesto es decir "amenaza" y no elegir
        # una categoría al azar.
        self.categoria_por_defecto = categoria_por_defecto
        self._domains: set[str] = set()
        self._categorias: dict[str, str] = {}
        self.reload()

    def reload(self) -> None:
        domains = set()
        categorias: dict[str, str] = {}
        for indice, path in enumerate(self.paths):
            if not path.exists():
                continue
            # El primer archivo es el manual; los demás vienen de feeds.
            categoria_actual = self.categoria_por_defecto if indice == 0 else "amenaza"
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.lower().startswith(MARCA_CATEGORIA):
                        categoria_actual = line.split(":", 1)[1].strip().lower() or "amenaza"
                        continue
                    if not line or line.startswith("#"):
                        continue
                    # Se normaliza la ENTRADA igual que se normaliza la
                    # consulta. Sin esto había un bypass de un solo carácter:
                    # un atacante publica su URL de phishing con un punto final
                    # en el host ("http://banco-falso.com./login", que funciona
                    # idéntico en todos los navegadores), el feed lo indexa así,
                    # y esa entrada NUNCA matchea ninguna consulta, porque del
                    # lado de la consulta el punto sí se saca. Lo mismo con los
                    # nombres internacionales, que los feeds publican en
                    # Unicode y las consultas llegan en punycode.
                    line = normalizar_nombre_consultado(line)
                    if line:
                        domains.add(line)
                        # setdefault: si un dominio está en dos feeds, se queda
                        # con el primero que lo vio. Sin esto, el orden de
                        # lectura decidiría en silencio si algo es "malware" o
                        # "publicidad", y cambiaría de un día para el otro.
                        categorias.setdefault(line, categoria_actual)
        self._domains = domains
        self._categorias = categorias

    def _coincidencia(self, domain: str) -> str | None:
        """La entrada de la lista que hace que este dominio esté bloqueado.

        Devuelve el dominio exacto si está, o el dominio padre que lo cubre
        (las listas cubren subdominios), o None.
        """
        # Se normaliza igual que las entradas de la lista: comparar dos
        # cadenas que pasaron por normalizaciones distintas es la forma
        # clásica de que una regla no matchee.
        domain = normalizar_nombre_consultado(domain)
        if domain in self._domains:
            return domain
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self._domains:
                return candidate
        return None

    def is_blocked(self, domain: str) -> bool:
        return self._coincidencia(domain) is not None

    def categoria_de(self, domain: str) -> str:
        """Por qué categoría está bloqueado este dominio, o "" si no lo está."""
        coincidencia = self._coincidencia(domain)
        if coincidencia is None:
            return ""
        return self._categorias.get(coincidencia, "amenaza")

    def add_and_reload(self, domain: str) -> None:
        """Agrega un dominio al primer archivo (el manual, paths[0]) y
        recarga en caliente. Pensado para el botón "Permitir"/"Bloquear" del
        dashboard, y para la opción equivalente del menú .bat."""
        domain = domain.strip().lower().rstrip(".")
        if not domain:
            return
        target_path = self.paths[0]
        target_path.parent.mkdir(parents=True, exist_ok=True)
        if domain not in self.manual_entries():
            with open(target_path, "a", encoding="utf-8") as f:
                f.write(domain + "\n")
        self.reload()

    def remove_and_reload(self, domain: str) -> None:
        """Saca un dominio del primer archivo (el manual, paths[0]) y
        recarga en caliente. Solo afecta la lista manual: si el mismo
        dominio también está en un archivo generado por feeds automáticos
        (paths[1] en adelante), ese no se toca acá."""
        domain = domain.strip().lower().rstrip(".")
        target_path = self.paths[0]
        if not target_path.exists():
            return
        lines = target_path.read_text(encoding="utf-8").splitlines()
        kept = [line for line in lines if line.strip().lower() != domain]
        target_path.write_text(
            "\n".join(kept) + ("\n" if kept else ""), encoding="utf-8"
        )
        self.reload()

    def dominios(self) -> list[str]:
        """Todos los dominios cargados, de todos los archivos. Es distinto de
        `manual_entries`, que solo mira el archivo editable: esto sirve para
        contarlos en el panel ("ocultando 50 dominios de telemetría")."""
        return sorted(self._domains)

    def manual_entries(self) -> list[str]:
        """Dominios definidos a mano en el primer archivo (paths[0]), sin
        contar comentarios ni lo que viene de feeds automáticos. Pensado
        para mostrarlos en el dashboard."""
        target_path = self.paths[0]
        if not target_path.exists():
            return []
        entries = set()
        for line in target_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Normalizado, igual que en `reload`: esta lista se compara contra
            # nombres consultados (ver `_decidir` del resolver), y dos
            # normalizaciones distintas no se encuentran nunca.
            normalizado = normalizar_nombre_consultado(line)
            if normalizado:
                entries.add(normalizado)
        return sorted(entries)


class Allowlist(Blocklist):
    """Lista blanca de dominios: gana por sobre la blocklist. Misma
    convención que en SecureProxy (mismo nombre de clase, mismo archivo de
    formato, misma lógica de coincidencia y edición por dominio+subdominios)
    para que unificar ambos proyectos más adelante sea directo."""

    def is_allowed(self, domain: str) -> bool:
        return self.is_blocked(domain)
