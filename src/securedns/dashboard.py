"""Dashboard web para ver estadísticas del resolver DNS y administrar sus
listas.

Corre como un servidor HTTP aparte (el DNS habla su propio protocolo por
UDP/TCP en el puerto 53, no HTTP), con el mismo estilo visual y las mismas
convenciones que el dashboard de SecureProxy, para mantener consistencia
entre ambos proyectos.
"""

import html as html_lib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

from .blocklist import Allowlist, Blocklist
from .dns_server import ThreatIntelResolver
from .logger_db import LoggerDB
from .validation import is_valid_domain


class DashboardRequestHandler(BaseHTTPRequestHandler):
    logger_db: LoggerDB
    allowlist: Allowlist
    blocklist: Blocklist
    resolver: ThreatIntelResolver

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass

    def do_GET(self) -> None:  # noqa: N802
        parsed_path = urlsplit(self.path)
        clean_path = parsed_path.path.rstrip("/")
        routes = {
            "/allow": lambda: self._handle_list_edit(self.allowlist, parsed_path.query, add=True),
            "/unallow": lambda: self._handle_list_edit(self.allowlist, parsed_path.query, add=False),
            "/blockdomain": lambda: self._handle_list_edit(self.blocklist, parsed_path.query, add=True),
            "/unblockdomain": lambda: self._handle_list_edit(self.blocklist, parsed_path.query, add=False),
            "/clear-cache": self._handle_clear_cache,
            "/cache-count": self._handle_cache_count,
            "/config": lambda: self._handle_config_change(parsed_path.query),
        }
        if clean_path in routes:
            routes[clean_path]()
            return
        self._serve_dashboard()

    # ---------- configuración editable desde el dashboard ----------

    # Lista blanca explícita de lo que se puede tocar desde la web. Cada
    # opción dice si se aplica en caliente o si necesita reiniciar, y eso se
    # muestra en la página para no prometer de más.
    OPCIONES_EDITABLES = {
        "upstream_mode": {
            "seccion": "dns",
            "tipo": "opcion",
            "valores": ("dot", "udp"),
            "en_vivo": True,
        },
        "dot_fallback_to_udp": {"seccion": "dns", "tipo": "booleano", "en_vivo": True},
        "min_cache_ttl": {
            "seccion": "dns", "tipo": "numero", "min": 0, "max": 86400, "en_vivo": True,
        },
        "enable_ad_tracker_blocklist": {
            "seccion": "filtering", "tipo": "booleano", "en_vivo": False,
        },
    }

    def _handle_config_change(self, query_string: str) -> None:
        from .config_loader import PROJECT_ROOT
        from .config_writer import set_value

        params = parse_qs(query_string)
        clave = (params.get("k") or [""])[0]
        valor_crudo = (params.get("v") or [""])[0]
        spec = self.OPCIONES_EDITABLES.get(clave)
        if spec is None:
            self._redirect_to_dashboard()
            return

        if spec["tipo"] == "opcion":
            if valor_crudo not in spec["valores"]:
                self._redirect_to_dashboard()
                return
            valor = valor_crudo
        elif spec["tipo"] == "booleano":
            valor = valor_crudo.lower() in ("1", "true", "on", "si", "sí")
        else:
            try:
                valor = int(valor_crudo)
            except ValueError:
                self._redirect_to_dashboard()
                return
            if not (spec["min"] <= valor <= spec["max"]):
                self._redirect_to_dashboard()
                return

        set_value(PROJECT_ROOT / "config" / "config.yaml", spec["seccion"], clave, valor)

        # Lo que el resolver lee en cada consulta se puede cambiar en caliente.
        if spec["en_vivo"]:
            setattr(self.resolver, clave, valor)
            if clave == "upstream_mode":
                # Al cambiar de transporte conviene soltar las conexiones TLS
                # persistentes: si no, seguirían usándose las viejas.
                cerrar = getattr(self.resolver, "_dot_close", None)
                if cerrar is not None:
                    for ip in list(getattr(self.resolver, "_dot_conns", {})):
                        cerrar(ip)

        self._redirect_to_dashboard()

    def _render_config_panel(self) -> str:
        resolver = self.resolver
        modo = getattr(resolver, "upstream_mode", "dot")
        fallback = bool(getattr(resolver, "dot_fallback_to_udp", True))
        ttl = getattr(resolver, "min_cache_ttl", 30)

        from .config_loader import PROJECT_ROOT
        from .config_writer import read_value

        cfg_file = PROJECT_ROOT / "config" / "config.yaml"
        ads = bool(read_value(cfg_file, "filtering", "enable_ad_tracker_blocklist", False))

        def tarjeta_modo(valor: str, etiqueta: str, subtitulo: str,
                         descripcion: str, confirmacion: str) -> str:
            """Mismo patrón visual que el panel de SecureProxy: cada opción es
            una tarjeta, se ve cuál está en uso, y cambiar pide confirmación."""
            activo = modo == valor
            clase = "optcard activa" if activo else "optcard"
            if activo:
                accion = "<span class='badge-activo'>&#10003; en uso</span>"
            else:
                accion = (
                    f"<form method='get' action='/config' "
                    f"onsubmit=\"return confirm('{confirmacion}')\">"
                    f"<input type='hidden' name='k' value='upstream_mode'>"
                    f"<input type='hidden' name='v' value='{valor}'>"
                    f"<button type='submit'>Cambiar a este modo</button></form>"
                )
            return (
                f"<div class='{clase}'>"
                f"<div class='optcard-head'><span class='optcard-title'>{etiqueta}</span>"
                f"<span class='optcard-sub'>{subtitulo}</span></div>"
                f"<p class='hint'>{descripcion}</p>{accion}</div>"
            )

        def interruptor(clave: str, encendido: bool, texto_prender: str,
                        texto_apagar: str, confirmacion: str = "") -> str:
            nuevo = "0" if encendido else "1"
            texto = texto_apagar if encendido else texto_prender
            clase = "danger-btn" if encendido else "ok-btn"
            pill = "pill on" if encendido else "pill off"
            estado = "activado" if encendido else "desactivado"
            confirm = f" onsubmit=\"return confirm('{confirmacion}')\"" if confirmacion else ""
            # El botón va primero (pegado al margen izquierdo) y la leyenda
            # de estado a su derecha: se lee "qué puedo hacer" y después
            # "cómo está ahora", que es el orden natural al operar.
            return (
                f"<div class='fila-switch'>"
                f"<form method='get' action='/config'{confirm}>"
                f"<input type='hidden' name='k' value='{clave}'>"
                f"<input type='hidden' name='v' value='{nuevo}'>"
                f"<button class='{clase}' type='submit'>{texto}</button></form>"
                f"<span class='leyenda'>actualmente <span class='{pill}'>{estado}</span></span>"
                f"</div>"
            )

        aviso_udp = (
            "En modo UDP tus consultas DNS viajan en TEXTO PLANO: tu proveedor "
            "de internet puede ver qué dominios consultás. Usalo solo si tu red "
            "bloquea el cifrado. ¿Cambiar a texto plano?"
        )
        aviso_dot = "¿Volver a DNS-over-TLS? Las consultas vuelven a viajar cifradas."
        aviso_fallback = (
            "¿Exigir cifrado siempre? Si algún día tu red bloquea el puerto 853, "
            "no vas a poder resolver nombres (internet parecerá caído)."
            if fallback else
            "¿Permitir el respaldo en texto plano cuando el cifrado no esté disponible?"
        )
        aviso_ads = (
            "¿Desactivar el bloqueo de publicidad y rastreadores? Requiere reiniciar el resolver."
            if ads else
            "¿Activar el bloqueo de publicidad y rastreadores? Requiere reiniciar el "
            "resolver para descargar la lista. Alguna página podría verse distinta."
        )

        return f"""
    <h2>Transporte hacia los servidores upstream</h2>
    <p class="hint">Se aplica al instante, sin reiniciar.</p>
    <div class="opciones">
      {tarjeta_modo("dot", "DNS-over-TLS", "cifrado · recomendado",
                    "Las consultas viajan cifradas por el puerto 853: tu proveedor de internet no puede leer qué dominios consultás, y el certificado del servidor se valida para que nadie pueda hacerse pasar por él.",
                    aviso_dot)}
      {tarjeta_modo("udp", "UDP en texto plano", "clásico · sin cifrar",
                    "El modo tradicional por el puerto 53. Más compatible con redes que bloquean el 853, pero cualquiera en el camino puede ver qué dominios consultás.",
                    aviso_udp)}
    </div>

    <h2>Si el cifrado no está disponible</h2>
    <p class="hint">Cuando ningún servidor responde por TLS (redes que bloquean
    el puerto 853), ¿se permite consultar en texto plano? Activado prioriza que
    internet siga funcionando; desactivado prioriza privacidad estricta: sin
    cifrado, no se resuelve. Se aplica al instante.</p>
    {interruptor("dot_fallback_to_udp", fallback, "Permitir respaldo en texto plano", "Exigir cifrado siempre", aviso_fallback)}

    <h2>Bloqueo de publicidad y rastreadores</h2>
    <p class="hint">Categoría aparte de las amenazas: suma un feed de dominios
    de publicidad y tracking. Está separado a propósito, porque bloquear ads no
    es lo mismo que bloquear malware (alguna página puede depender de un
    tracker para verse bien). <strong>Requiere reiniciar el resolver</strong>
    para descargar y cargar la lista.</p>
    {interruptor("enable_ad_tracker_blocklist", ads, "Activar", "Desactivar", aviso_ads)}

    <h2>Caché mínimo de respuestas</h2>
    <p class="hint">Segundos que se guarda una respuesta como mínimo, aunque su
    propio TTL sea menor. Más alto = menos consultas salientes y más velocidad;
    más bajo = cambios de DNS se reflejan antes. Se aplica al instante.</p>
    <form class="add-form" method="get" action="/config">
      <input type="hidden" name="k" value="min_cache_ttl">
      <input type="number" name="v" min="0" max="86400" value="{ttl}" required>
      <button type="submit">Guardar</button>
    </form>
    <p class="hint">Actual: <strong>{ttl}</strong> segundos (default: 30)</p>

    <h2>Lo que se cambia desde el archivo</h2>
    <p class="hint">Necesitan reiniciar y viven en <code>config/config.yaml</code>:
    los servidores upstream (hoy Quad9 y Cloudflare) con sus nombres de
    certificado, el puerto donde escucha el resolver, el del dashboard, y cada
    cuánto se refrescan los feeds de amenazas.</p>
"""

    def _handle_cache_count(self) -> None:
        """Devuelve solo el número de entradas en el cache de respuestas, en
        texto plano. Pensado para que la opción "Ver estado" del menú .bat
        pueda mostrarlo sin tener que levantar/parsear todo el HTML del
        dashboard (el cache es en memoria del proceso, así que no hay forma
        de leerlo desde afuera sin pasar por acá)."""
        body = str(self.resolver.cache_size()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _redirect_to_dashboard(self) -> None:
        """Misma lógica que en SecureProxy: cierra la conexión en vez de
        mantener keep-alive, para que una pestaña que quedó en segundo plano
        no termine intentando reusar una conexión que el servidor ya cerró
        por inactividad (la causa más probable de que el dashboard se quede
        "pensando" a veces)."""
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _handle_list_edit(self, target_list, query_string: str, add: bool) -> None:
        """Igual que en SecureProxy: al agregar, valida que el texto tenga
        forma de dominio antes de escribirlo en el archivo de lista, para no
        ensuciarla con URLs completas o strings pegados por error."""
        params = parse_qs(query_string)
        domain = (params.get("domain") or [""])[0].strip()
        if domain:
            if add:
                if is_valid_domain(domain):
                    target_list.add_and_reload(domain)
            else:
                target_list.remove_and_reload(domain)
        self._redirect_to_dashboard()

    def _handle_clear_cache(self) -> None:
        self.resolver.clear_cache()
        self._redirect_to_dashboard()

    @staticmethod
    def _render_editable_list(items: list[str], remove_endpoint: str) -> str:
        if not items:
            return "<p class='empty'>No hay dominios cargados todavía.</p>"
        rows = "".join(
            f"<tr><td>{html_lib.escape(domain)}</td>"
            f"<td><a class='danger' href=\"{remove_endpoint}?domain={quote(domain)}\" "
            f"onclick=\"return confirm('¿Quitar ' + '{html_lib.escape(domain)}' + '?')\">Quitar</a></td></tr>"
            for domain in items
        )
        return f"<table><tr><th>Dominio</th><th>Acción</th></tr>{rows}</table>"

    def _serve_dashboard(self) -> None:
        stats = self.logger_db.stats()
        total = stats["total_queries"]
        blocked = stats["blocked_queries"]
        cached = stats["cached_queries"]
        block_rate = (blocked / total * 100) if total else 0.0
        cache_entries = self.resolver.cache_size()

        rows = self.logger_db.recent_blocked(limit=25)
        if rows:
            rows_html = "".join(
                f"<tr><td>{html_lib.escape(str(ts))}</td>"
                f"<td>{html_lib.escape(str(domain))}</td>"
                f"<td>{html_lib.escape(str(reason))}</td>"
                f"<td><a href=\"/allow?domain={quote(str(domain))}\" "
                f"onclick=\"return confirm('¿Permitir siempre ' + '{html_lib.escape(str(domain))}' + '?')\">"
                f"Permitir</a></td></tr>"
                for ts, domain, reason in rows
            )
        else:
            rows_html = "<tr><td colspan='4'>Todavía no se bloqueó ninguna consulta.</td></tr>"

        allowlist_html = self._render_editable_list(self.allowlist.manual_entries(), "/unallow")
        blocklist_html = self._render_editable_list(self.blocklist.manual_entries(), "/unblockdomain")

        config_html = self._render_config_panel()

        page = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>SecureDNS - Dashboard</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, "Segoe UI", sans-serif; background:#0f1115; color:#e6e6e6; padding:2rem; max-width: 960px; margin: 0 auto; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.1rem; }}
  .subtitle {{ color:#9aa0a6; font-size:0.85rem; margin-top:0; }}
  .stats {{ display:flex; gap:1.25rem; margin: 1.5rem 0; flex-wrap: wrap; align-items: stretch; }}
  .card {{ background:#1a1d24; border-radius:8px; padding:1rem 1.5rem; min-width:140px; }}
  .card .value {{ font-size:1.8rem; font-weight:600; }}
  .card .label {{ color:#9aa0a6; font-size:0.85rem; }}
  .card.action {{ display:flex; align-items:center; justify-content:center; }}
  table {{ width:100%; border-collapse: collapse; margin-top:0.5rem; }}
  th, td {{ text-align:left; padding:0.5rem 0.75rem; border-bottom:1px solid #2a2e37; font-size:0.85rem; }}
  th {{ color:#9aa0a6; font-weight:500; }}
  .empty {{ color:#9aa0a6; font-size:0.85rem; }}
  .hint {{ color:#9aa0a6; font-size:0.82rem; }}
  code {{ background:#1a1d24; padding:0.1rem 0.35rem; border-radius:4px; }}
  h2 {{ margin-top:1.6rem; margin-bottom:0.3rem; }}
  .opciones {{ display:flex; gap:0.9rem; flex-wrap:wrap; margin:0.9rem 0 0.4rem; }}
  .optcard {{ flex:1 1 260px; background:#161922; border:1px solid #2a2e37; border-radius:10px; padding:0.9rem 1rem; }}
  .optcard.activa {{ border-color:#3f7d52; background:#16241a; }}
  .optcard-head {{ display:flex; align-items:baseline; gap:0.5rem; flex-wrap:wrap; margin-bottom:0.35rem; }}
  .optcard-title {{ font-size:1rem; font-weight:600; }}
  .optcard-sub {{ font-size:0.75rem; color:#9aa0a6; text-transform:uppercase; letter-spacing:0.04em; }}
  .optcard .hint {{ margin:0 0 0.7rem; line-height:1.45; }}
  .optcard button {{ width:100%; }}
  .badge-activo {{ display:inline-block; background:#1e3a26; color:#7bd88f; border-radius:6px; padding:0.4rem 0.8rem; font-size:0.85rem; }}
  .fila-switch {{ display:flex; align-items:center; gap:0.75rem; margin:0.6rem 0 0.2rem; flex-wrap:wrap; }}
  .pill {{ display:inline-block; border-radius:999px; padding:0.25rem 0.75rem; font-size:0.78rem; font-weight:600; }}
  .pill.on {{ background:#1e3a26; color:#7bd88f; }}
  .pill.off {{ background:#24262e; color:#9aa0a6; }}
  .leyenda {{ color:#9aa0a6; font-size:0.85rem; }}
  button:hover {{ filter:brightness(1.25); }}
  button {{ transition:filter 0.15s ease; }}
  .add-form input[type=number] {{ background:#1a1d24; border:1px solid #2a2e37; color:#e6e6e6; border-radius:6px; padding:0.5rem 0.75rem; width:110px; }}
  button.ok-btn {{ background:#1e3a26; color:#7bd88f; }}
  a {{ color:#7fb2ff; }}
  a.danger {{ color:#ff8a8a; }}
  .tabs {{ display:flex; gap:0.5rem; margin-top:1.5rem; border-bottom:1px solid #2a2e37; }}
  /* border-radius:0 explícito: las pestañas son <button> y heredaban el
     redondeo de la regla general, lo que curvaba las puntas de la línea
     azul del subrayado. Acá la línea tiene que ser recta. */
  .tab-btn {{ background:none; border:none; border-radius:0; color:#9aa0a6; font-size:0.9rem; font-family:inherit; padding:0.6rem 1rem; cursor:pointer; border-bottom:2px solid transparent; }}
  .tab-btn.active {{ color:#e6e6e6; border-bottom:2px solid #7fb2ff; }}
  .tab-panel {{ display:none; padding-top:1rem; }}
  .tab-panel.active {{ display:block; }}
  .add-form {{ display:flex; gap:0.5rem; margin-bottom:1rem; }}
  .add-form input[type=text] {{ flex:1; background:#1a1d24; border:1px solid #2a2e37; color:#e6e6e6; border-radius:6px; padding:0.5rem 0.75rem; }}
  button {{ background:#2a2e37; border:none; color:#e6e6e6; border-radius:6px; padding:0.5rem 1rem; cursor:pointer; font-size:0.85rem; font-family:inherit; }}
  button.danger-btn {{ background:#3a1f22; color:#ff8a8a; }}
</style>
</head>
<body>
  <h1>SecureDNS</h1>
  <p class="subtitle">Panel de control - se actualiza solo cada 5 segundos</p>
  <div class="stats">
    <div class="card"><div class="value">{total}</div><div class="label">Consultas totales</div></div>
    <div class="card"><div class="value">{blocked}</div><div class="label">Bloqueadas</div></div>
    <div class="card"><div class="value">{block_rate:.1f}%</div><div class="label">Tasa de bloqueo</div></div>
    <div class="card"><div class="value">{cached}</div><div class="label">Respondidas desde caché</div></div>
    <div class="card"><div class="value">{cache_entries}</div><div class="label">Entradas en cache ahora</div></div>
    <div class="card action">
      <form method="get" action="/clear-cache" onsubmit="return confirm('¿Borrar el cache de respuestas DNS?')">
        <button type="submit" class="danger-btn">Borrar cache</button>
      </form>
    </div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" data-tab="bloqueos" onclick="showTab('bloqueos', this)">Bloqueos</button>
    <button class="tab-btn" data-tab="blanca" onclick="showTab('blanca', this)">Lista blanca</button>
    <button class="tab-btn" data-tab="negra" onclick="showTab('negra', this)">Lista negra (manual)</button>
    <button class="tab-btn" data-tab="config" onclick="showTab('config', this)">Configuración</button>
  </div>

  <div id="tab-bloqueos" class="tab-panel active">
    <h2>Últimos bloqueos</h2>
    <table>
      <tr><th>Fecha/hora (UTC)</th><th>Dominio</th><th>Motivo</th><th>Acción</th></tr>
      {rows_html}
    </table>
  </div>

  <div id="tab-blanca" class="tab-panel">
    <h2>Lista blanca</h2>
    <p class="empty">Un dominio acá gana por sobre la blocklist.</p>
    <form class="add-form" method="get" action="/allow">
      <input type="text" name="domain" placeholder="ejemplo.com" required>
      <button type="submit">Agregar</button>
    </form>
    {allowlist_html}
  </div>

  <div id="tab-negra" class="tab-panel">
    <h2>Lista negra (manual)</h2>
    <p class="empty">Solo la lista manual (data/blocklist.txt). Lo generado por
    URLhaus/OpenPhish no se administra desde acá.</p>
    <form class="add-form" method="get" action="/blockdomain">
      <input type="text" name="domain" placeholder="ejemplo.com" required>
      <button type="submit">Agregar</button>
    </form>
    {blocklist_html}
  </div>

  <div id="tab-config" class="tab-panel">
    {config_html}
  </div>

<script>
var TAB_STORAGE_KEY = 'securedns_dashboard_tab';
function showTab(name, btn) {{
  document.querySelectorAll('.tab-panel').forEach(function(el) {{ el.classList.remove('active'); }});
  document.querySelectorAll('.tab-btn').forEach(function(el) {{ el.classList.remove('active'); }});
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
  try {{ localStorage.setItem(TAB_STORAGE_KEY, name); }} catch (e) {{ /* sin soporte de localStorage: no pasa nada */ }}
}}
(function() {{
  // Restaura la pestaña que se estaba mirando antes del refresco automático
  // de cada 5 segundos, en vez de volver siempre a "Bloqueos".
  var saved = null;
  try {{ saved = localStorage.getItem(TAB_STORAGE_KEY); }} catch (e) {{ /* nada */ }}
  if (saved) {{
    var btn = document.querySelector('.tab-btn[data-tab="' + saved + '"]');
    if (btn) {{ showTab(saved, btn); }}
  }}
}})();
</script>
</body>
</html>"""

        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


def build_dashboard_server(
    host: str,
    port: int,
    logger_db: LoggerDB,
    allowlist: Allowlist,
    blocklist: Blocklist,
    resolver: ThreatIntelResolver,
) -> ThreadingHTTPServer:
    handler_class = type(
        "InjectedDashboardHandler",
        (DashboardRequestHandler,),
        {
            "logger_db": logger_db,
            "allowlist": allowlist,
            "blocklist": blocklist,
            "resolver": resolver,
        },
    )
    server = ThreadingHTTPServer((host, port), handler_class)
    server.daemon_threads = True
    return server
