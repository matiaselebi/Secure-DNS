"""Lista negra de dominios, cargada desde uno o varios archivos de texto."""

from pathlib import Path


class Blocklist:
    """Combina una lista curada a mano con una generada automáticamente
    (feeds de amenazas), sin que se pisen entre sí."""

    def __init__(self, path: str | list[str]):
        if isinstance(path, str):
            path = [path]
        self.paths = [Path(p) for p in path]
        self._domains: set[str] = set()
        self.reload()

    def reload(self) -> None:
        domains = set()
        for path in self.paths:
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and not line.startswith("#"):
                            domains.add(line)
        self._domains = domains

    def is_blocked(self, domain: str) -> bool:
        domain = domain.lower().rstrip(".")
        if domain in self._domains:
            return True
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self._domains:
                return True
        return False

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

    def manual_entries(self) -> list[str]:
        """Dominios definidos a mano en el primer archivo (paths[0]), sin
        contar comentarios ni lo que viene de feeds automáticos. Pensado
        para mostrarlos en el dashboard."""
        target_path = self.paths[0]
        if not target_path.exists():
            return []
        entries = set()
        for line in target_path.read_text(encoding="utf-8").splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                entries.add(line)
        return sorted(entries)


class Allowlist(Blocklist):
    """Lista blanca de dominios: gana por sobre la blocklist. Misma
    convención que en SecureProxy (mismo nombre de clase, mismo archivo de
    formato, misma lógica de coincidencia y edición por dominio+subdominios)
    para que unificar ambos proyectos más adelante sea directo."""

    def is_allowed(self, domain: str) -> bool:
        return self.is_blocked(domain)
