# SecureDNS

![CI](https://github.com/matiaselebi/secure-dns/actions/workflows/ci.yml/badge.svg)

Resolver DNS local con filtrado de dominios maliciosos conocidos. Es una
capa de un stack personal de seguridad en profundidad ("defense in depth")
junto con [SecureProxy](https://github.com/matiaselebi/secure-proxy) (filtrado
de tráfico de aplicaciones) y una futura VPN casera (SecureVPN, transporte
cifrado): mientras el proxy filtra el tráfico de las aplicaciones que lo
tienen configurado, este DNS filtra a nivel de resolución de nombres,
cubriendo también aplicaciones que no respetan la configuración de proxy
del sistema. Ver "Qué NO hace" más abajo para los límites explícitos de
alcance de este proyecto en particular.

## Qué hace

- Escucha consultas DNS (UDP) en `127.0.0.1`, pensado para uso en una sola
  máquina (no expone el servicio a toda una red local).
- Antes de resolver cualquier dominio, primero chequea si está en la
  **lista blanca** (`data/allowlist.txt`): si es así, se resuelve
  normalmente sin más chequeos. Si no, lo chequea contra la lista negra
  (curada a mano + generada automáticamente desde URLhaus y OpenPhish). Si
  está bloqueado, responde `NXDOMAIN` de inmediato, sin salir a internet.
- Lo que no está bloqueado se reenvía a un servidor DNS upstream: **Quad9**
  (`9.9.9.9`) como principal, que además filtra malware conocido por su
  cuenta, y **Cloudflare** (`1.1.1.1`) como respaldo si Quad9 no responde.
- La charla con esos upstreams va **cifrada con DNS-over-TLS (DoT)** por
  defecto: tu proveedor de internet (o cualquiera espiando la red) ya no
  puede leer qué dominios consultás. Si la red bloquea el puerto 853 (pasa
  en algunas redes públicas), cae automáticamente a UDP en texto plano para
  que internet siga funcionando — comportamiento configurable si preferís
  privacidad estricta. Implementado solo con la librería estándar de Python
  (`ssl` + `socket`): cero dependencias nuevas y cero criptografía propia;
  el TLS y la validación de certificados los hace la librería estándar.
- Cachea las respuestas según su propio TTL, para no consultar de nuevo un
  dominio ya resuelto recientemente.
- Cada consulta (bloqueada, cacheada, o resuelta) queda registrada en
  SQLite, visible en un dashboard web con el mismo estilo que SecureProxy.

## Qué NO hace (alcance del proyecto)

Este proyecto está limitado a resolución recursiva/forwarding con filtrado
de amenazas para una sola máquina. Explícitamente fuera de alcance, y por
qué:

- **No sirve DNS para toda una red local** (no es para el router de tu
  casa): eso requeriría que la máquina esté siempre encendida y accesible
  desde otros dispositivos, un caso de uso distinto al de este proyecto.
- **No administra un dominio público** (zonas, registros TXT de
  verificación, SPF/DKIM/DMARC): estas funciones son para quien es dueño y
  administra el DNS de un dominio real, un problema distinto al de filtrar
  las consultas salientes de una PC.
- **No implementa mDNS** (descubrimiento de dispositivos tipo Chromecast):
  es un protocolo distinto (multicast, puerto 5353), no una extensión de un
  resolver DNS convencional.
- **No hace geolocalización ni balanceo de carga geográfico**: esas son
  funciones que implementan los *proveedores* de contenido (Netflix,
  Cloudflare), no algo que un resolver casero necesite construir.

## Estructura del proyecto

```
secure-dns/
├── README.md
├── requirements.txt
├── .gitignore
├── LICENSE
├── config/
│   └── config.yaml
├── data/
│   ├── blocklist.txt
│   └── allowlist.txt       # lista blanca de dominios (curada a mano o vía dashboard)
├── src/securedns/
│   ├── __init__.py
│   ├── config_loader.py
│   ├── logger_db.py
│   ├── blocklist.py        # Blocklist + Allowlist
│   ├── dns_server.py       # resolver: allowlist + filtrado + caché + upstream con fallback
│   └── dashboard.py        # dashboard web + endpoint "Permitir"
├── scripts/
│   ├── run_dns.py
│   ├── stop_dns.py
│   └── update_blocklist.py
├── SecureDNS.bat           # panel de control para Windows
├── tests/
│   ├── test_blocklist.py
│   ├── test_logger_db.py
│   ├── test_dns_server.py
│   ├── test_dashboard.py
│   └── test_update_blocklist.py
├── docker/
│   └── Dockerfile
└── .github/workflows/ci.yml
```

## Instalación

### Windows

```powershell
git clone https://github.com/matiaselebi/secure-dns.git
cd secure-dns
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Linux / macOS

```bash
git clone https://github.com/matiaselebi/secure-dns.git
cd secure-dns
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Uso

En primer plano:

```bash
python scripts/run_dns.py
```

En Windows, la forma más simple es `SecureDNS.bat`, que ofrece un panel con
8 opciones:

1. **Iniciar DNS**: registra el inicio automático con Windows, arranca el
   resolver de inmediato, y configura `127.0.0.1` como servidor DNS en todos
   los adaptadores de red activos (equivalente a hacerlo a mano desde
   Configuración → Red e Internet → DNS, pero automático).
2. **Detener DNS**: quita el inicio automático, vuelve el DNS de los
   adaptadores a automático (DHCP), y detiene el proceso.
3. **Ver estado**: si el inicio automático está activo, si el proceso está
   corriendo, qué DNS tiene configurado cada adaptador en este momento, y
   cuántas entradas tiene el cache ahora (solo si el resolver está
   corriendo, porque ese cache vive en memoria, sin persistencia en disco).
4. **Actualizar listas de amenazas**: fuerza la descarga de URLhaus y
   OpenPhish. El resolver también lo hace solo, en segundo plano, respetando
   un intervalo mínimo configurable (6 horas por defecto).
5. **Agregar dominio a la lista blanca**: pide el dominio por teclado y lo
   agrega a `data/allowlist.txt`. Si el resolver está corriendo, se aplica
   solo en unos segundos (recarga automática cada 15 segundos), sin
   necesidad de reiniciar el proceso.
6. **Agregar dominio a la lista negra**: igual que la anterior, pero a
   `data/blocklist.txt` (la lista manual).
7. **Borrar cache de respuestas DNS**: si el resolver está corriendo, lo
   vacía al instante (llama al mismo endpoint que el botón del dashboard).
   Si no está corriendo, no hay nada que borrar (el cache es en memoria).
8. **Salir**.

Requiere permisos de administrador (se auto-eleva pidiéndolos si hace
falta), porque cambiar el DNS de un adaptador de red y registrar tareas
programadas necesita ese nivel de acceso en Windows.

### Dashboard

Con el resolver corriendo, entrando a `http://127.0.0.1:8890/` se ve un
panel con el total de consultas, cuántas se cachearon, la tasa de bloqueo,
cuántas entradas hay ahora en el cache, y tres pestañas: **Bloqueos**
(cada uno con un link "Permitir"), **Lista blanca** y **Lista negra
(manual)** — en estas dos últimas se puede agregar un dominio con un
formulario o sacar uno existente con "Quitar", sin editar ningún archivo a
mano. También hay un botón **"Borrar cache"** que vacía el cache de
respuestas DNS en memoria. Se refresca solo cada 5 segundos, y recuerda qué
pestaña tenías abierta entre refrescos.

Igual que en SecureProxy, cada acción del dashboard cierra la conexión
HTTP en vez de mantenerla abierta, para evitar el cuelgue ocasional que
podía pasar si el navegador dejaba la pestaña en segundo plano.

### Probarlo sin cambiar la configuración de red

```bash
python -c "
import socket
from dnslib import DNSRecord
q = DNSRecord.question('example.com')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(q.pack(), ('127.0.0.1', 53))
print(DNSRecord.parse(s.recvfrom(512)[0]))
"
```

## Historial de bloqueos

Igual que en SecureProxy: el historial de la pestaña "Bloqueos" es
**acumulado desde la primera vez que corriste el resolver**, no solo desde
el último arranque. Cada consulta (bloqueada, cacheada o resuelta) se
guarda en `data/dns_logs.db` (SQLite), que persiste en disco entre
reinicios, y el dashboard siempre muestra las últimas 25 bloqueadas de esa
base completa.

Si un dominio que esperabas ver bloqueado no aparece, lo más probable es
que la consulta nunca haya llegado a este resolver — por ejemplo, si la
app usa su propio DNS interno (algunos navegadores con "DNS sobre HTTPS"
activado ignoran el DNS del sistema operativo), o si el adaptador de red
que estás usando en ese momento no tiene `127.0.0.1` configurado como su
DNS. Para confirmar, mirá el total de "Consultas totales" del dashboard
mientras reproducís el caso: si no se mueve, la consulta no está pasando
por acá.

## Configuración (`config/config.yaml`)

- `dns.host` / `dns.port`: dirección y puerto donde escucha (default
  `127.0.0.1:53`).
- `dns.upstream_primary` / `dns.upstream_fallback`: servidores DNS a los que
  se reenvía lo que no está bloqueado (default Quad9 + Cloudflare).
- `dns.upstream_mode`: `"dot"` (DNS-over-TLS cifrado, puerto 853, default) o
  `"udp"` (texto plano clásico, puerto 53).
- `dns.upstream_primary_tls_name` / `dns.upstream_fallback_tls_name`: nombre
  que debe figurar en el certificado TLS de cada upstream (solo modo `dot`).
  Si el certificado no coincide, la conexión se rechaza — esto impide que
  alguien en la red se haga pasar por Quad9/Cloudflare.
- `dns.dot_fallback_to_udp`: si ningún upstream respondió por TLS, `true`
  (default) permite caer a UDP plano para no quedarse sin internet; `false`
  responde `SERVFAIL` antes que consultar sin cifrar (privacidad estricta).
- `dns.upstream_timeout`: segundos de espera antes de intentar el respaldo.
- `dns.min_cache_ttl`: TTL mínimo de caché, aunque la respuesta real traiga
  uno menor.
- `filtering.blocklist_path` / `filtering.feeds_blocklist_path`: listas
  manual y automática de dominios bloqueados.
- `filtering.allowlist_path`: lista blanca manual (o vía el botón "Permitir"
  del dashboard). Gana por sobre la blocklist.
- `filtering.feeds_update_interval_hours`: cada cuánto se refresca la lista
  automática al arrancar (default 6 horas).
- `filtering.enable_ad_tracker_blocklist`: `false` por defecto. Si es
  `true`, además de la blocklist de amenazas se descarga y aplica una
  lista de dominios de publicidad/tracking (feed StevenBlack/hosts) como
  categoría separada - ver "Bloqueo opcional de ads/trackers" abajo y
  [ADR 0003](docs/adr/0003-optional-ad-tracker-category.md).
- `filtering.ad_tracker_blocklist_path`: archivo donde se guarda esa lista
  opcional (default `data/blocklist_adtracker.txt`).

## Bloqueo opcional de ads/trackers

Aparte de la blocklist de amenazas (malware, phishing, C2), se puede activar
una categoría separada de dominios de publicidad/tracking (feed
StevenBlack/hosts) con `filtering.enable_ad_tracker_blocklist: true` en
`config/config.yaml`. Se mantiene en su propio archivo
(`data/blocklist_adtracker.txt`), separado de la blocklist de amenazas, y
desactivada por defecto: bloquear ads no es lo mismo que bloquear amenazas
activas, y algún sitio puede depender visualmente de un tracker para cargar
contenido - por eso es opt-in explícito y no viene mezclado con la lista de
seguridad. Detalle en
[ADR 0003](docs/adr/0003-optional-ad-tracker-category.md).

## Validación de dominios en el dashboard

Igual que en SecureProxy: los formularios de "Lista blanca" y "Lista negra"
del dashboard validan que el texto ingresado tenga forma de dominio o IP
antes de escribirlo en el archivo correspondiente
(`src/securedns/validation.py`), para evitar que una URL completa pegada
por error termine guardada tal cual y no matchee nunca contra un hostname
real.

## Tests

```bash
pytest tests/ -v
```

Cobertura: lista negra y lista blanca (exacta, subdominios, combinación de
archivos), resolución con allowlist/bloqueo/caché/fallback de upstream
(probado con servidores de prueba locales, sin depender de la red real),
dashboard (incluido el flujo completo de "Permitir" y el rechazo de
dominios mal formados), validación de formato de dominio, parseo de los
feeds de amenazas y del feed opcional de ads/trackers, y el modo
DNS-over-TLS: framing TCP (con streams fragmentados y conexiones rotas a
mitad de respuesta), elección de camino DoT/UDP según la configuración,
reintento con conexión nueva cuando la persistente murió, y un test de
integración real contra Quad9 por TLS que se salta solo si la red donde
corre bloquea el puerto 853.

## Docker

```bash
docker build -t secure-dns -f docker/Dockerfile .
docker run -p 127.0.0.1:53:53/udp -p 8890:8890 secure-dns
```

## Decisiones de diseño (ADRs)

Decisiones de arquitectura no triviales (por qué solo UDP entrante y una
sola máquina, por qué DoT con fallback a UDP en vez de DoH, por qué el
bloqueo de ads/trackers es una categoría separada opt-in) están
documentadas en `docs/adr/`, con el contexto y las consecuencias aceptadas
de cada una.

Las dependencias (`requirements.txt` y las Actions del CI) se mantienen
actualizadas automáticamente vía Dependabot (`.github/dependabot.yml`,
chequeo semanal).

## Roadmap

- Bloqueo también por IP de destino (usando Feodo Tracker), verificando la
  IP que devuelve el upstream antes de responder al cliente - más complejo
  porque requiere resolver primero y decidir después.
- Soporte TCP además de UDP del lado que escucha (hoy las consultas
  *entrantes* son solo UDP, que cubre la gran mayoría de los casos reales;
  hacia los upstreams ya se habla TCP+TLS con el modo DoT).
- Nombres locales personalizados para dispositivos de tu red (ej.
  `nas.local` → `192.168.1.50`).
- Dashboard unificado con SecureProxy cuando se integren ambos proyectos.

## Aviso

Proyecto educativo/de portfolio. Pensado para uso personal en una sola
máquina, no para producción ni para servir DNS a una red de terceros.

## Autor

Matias Elebi - [LinkedIn](https://www.linkedin.com/in/matiaselebi/) · [GitHub](https://github.com/matiaselebi)

## Licencia

MIT
