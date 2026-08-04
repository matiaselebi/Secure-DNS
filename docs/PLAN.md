# SecureDNS: qué falta, en qué orden, y qué queda afuera

Este documento evalúa las 26 ideas propuestas para SecureDNS. Para cada una
dice si entra o no, y **por qué**. Las que no entran están todas al final, con
el motivo, porque una lista de descartes sin explicación es una lista que
alguien vuelve a proponer en dos meses.

El criterio para decidir fue siempre el mismo, y conviene dejarlo escrito
porque es el que resuelve casi todos los casos dudosos:

1. **¿Lo puede ver un resolver?** El DNS traduce nombres. No ve el contenido
   de una conexión, ni si el sitio habla HTTPS, ni qué proceso la abrió. Todo
   lo que necesite eso es del proxy.
2. **¿Hay una fuente real para el dato?** Un número sin fuente es un número
   inventado, y en una herramienta de seguridad eso es peor que no tenerlo.
3. **¿Es de esta herramienta o de SecureCenter?** Correlacionar las tres
   herramientas es la razón de existir de SecureCenter. Si SecureDNS lo hace
   por su cuenta, SecureCenter se queda sin nada que hacer y el portfolio
   muestra dos paneles que hacen lo mismo.
4. **¿Señala o bloquea?** Los detectores por comportamiento tienen falsos
   positivos. Ya está decidido en el ADR 0007 de SecureProxy: **señalan, no
   bloquean**. Un DNS que corta por su cuenta te deja sin internet.

---

## Fase 0: hecho

**Los 50 dominios de telemetría plegados** (idea 26). La lista se mostraba
entera y tapaba el resto de la configuración. Ahora está adentro de un
desplegable, igual que en SecureProxy, y arriba quedó el formulario para
agregar los tuyos.

---

## Fase 1: lo que ya está pago

Todo esto sale de datos que **ya se están guardando** en `data/dns_logs.db` y
que hoy no se muestran en ningún lado. Es la fase de mejor relación entre lo
que se ve y lo que cuesta.

**Latencia y tiempo de resolución** (ideas 7 y 9). La columna `duration_ms` se
escribe en cada consulta desde siempre y no se usa. Falta el promedio, el
máximo, el mínimo y un gráfico. Sirve de verdad: si el promedio se dispara,
algo pasa con el upstream o con la red.

**Cache hit ratio** (idea 8). Ya se guarda `source='cache'`. Mostrar
"33% desde caché / 67% consultado" en vez de un número absoluto es más
informativo y es una división.

**Equipos con más bloqueos** (idea 14). La consulta `top_clientes` ya devuelve
total y bloqueadas por cliente; el panel muestra solo el total. Ordenar por
bloqueos es otra vista de datos que ya están.

**Categorías de amenaza** (ideas 4 y 21, en su versión honesta). No inventando
una "reputación", sino diciendo **en qué lista apareció**: URLhaus es malware,
OpenPhish es phishing, StevenBlack es publicidad y tracking, la lista de pools
es minería. Eso es una categoría con fuente. Requiere etiquetar el motivo del
bloqueo con su categoría al momento de bloquear.

**Detalle por consulta** (parte de la idea 1). Un desplegable por fila del
historial con todo lo que se sabe de esa consulta, igual que el acordeón de
SecureProxy. Ojo que esto es distinto del score: el score es global, no va
fila por fila.

**Modos de bloqueo** (idea 19). Hoy siempre se responde `NXDOMAIN`. Sumar
`0.0.0.0` y `127.0.0.1` como opciones. No es cosmético: `NXDOMAIN` rompe
algunas aplicaciones que lo interpretan como "la red está caída", mientras que
`0.0.0.0` falla más rápido y más limpio. Es lo que hace Pi-hole y por el mismo
motivo.

**Exportar CSV y JSON** (parte de la idea 16). Ya está resuelto en
SecureProxy, se porta.

---

## Fase 2: el diferencial

Esto es lo único de toda la lista que **solo un resolver puede ver**. Es lo que
separa el proyecto de "otro Pi-hole".

**Detección de DNS tunneling** (idea 2). Las señales propuestas son las
correctas y se combinan, ninguna alcanza sola:

- proporción de consultas `TXT` y `NULL` sobre el total de un cliente
- longitud promedio de las etiquetas del nombre
- entropía de los subdominios (los generados por algoritmo no se parecen a
  palabras)
- cantidad de subdominios **distintos** bajo un mismo dominio padre
- ráfaga de consultas al mismo padre en poco tiempo

**Comportamiento anómalo por cliente** (ideas 22 y 23). Un equipo que hace 500
consultas por hora y de golpe hace 15.000. Comparte la misma maquinaria que lo
anterior (línea de base por cliente y desvío), por eso va en la misma fase y
no en otra.

Las dos **señalan, no bloquean**, por el criterio 4 de arriba. Y las dos van a
necesitar su propio ADR explicando los umbrales elegidos y por qué.

---

## Fase 3: inteligencia externa

Acá el resolver empieza a preguntarle cosas a terceros. Todo lo de esta fase
tiene que ser **opt-in, cacheado y fail-open**: si la fuente externa no
responde, el resolver sigue resolviendo.

**DNSSEC** (idea 5). La respuesta del upstream trae el flag `AD`
(*Authenticated Data*). Es leer un bit, y da para una estadística de qué
porcentaje de lo que consultás está firmado. Con una salvedad que hay que
escribir en el panel y no esconder: ese flag significa **"Quad9 validó esto"**,
no "yo lo validé". Decir "dominio firmado" a secas sería atribuirse una
validación que no se hizo.

**País, ASN y proveedor del destino** (ideas 10 y 12). La respuesta DNS ya trae
las IPs, así que no hace falta resolver nada de nuevo: alcanza con pasarlas por
la base local de geolocalización. Se reusa el `geoip.py` de SecureProxy, que ya
existe y ya tiene su ADR (el 0004, sobre por qué es una base local y no una
API). Nada sale a internet.

**Edad del dominio** (ideas 3 y 11). Se hace con RDAP, que es el reemplazo
moderno y estandarizado de WHOIS, gratis y con respuesta JSON. Muchísimo
malware usa dominios registrados hace días, así que la señal es buena.

Pero tiene un costo que hay que decir en voz alta: **cada consulta RDAP le
avisa a un tercero qué dominio estás mirando**, que es exactamente lo que el
proyecto evita poniendo DNS-over-TLS. Por eso va apagado por defecto, con
cache en disco, y solo para dominios que ya llamaron la atención por otra
razón. No para todo lo que se consulta.

**Estadísticas históricas** (idea 20). Hoy el historial se recorta a 200.000
filas. Mostrar "12 meses" sobre una base que ya podó los datos viejos sería
mentir. La solución honesta es una tabla de resúmenes diarios que sobreviva a
la poda: se guarda el agregado del día y se puede borrar el detalle. Es trabajo
real, no un botón, por eso está acá y no en la Fase 1.

---

## Fase 4: integración con el resto de la suite

**API REST de solo lectura** (idea 17). Vale la pena, pero por un motivo que no
estaba en la propuesta original: **es cómo debería hablar SecureCenter con las
tres herramientas.** Hoy no hay contrato entre ellas. Si la API se diseña acá y
después se porta a las otras dos, se resolvió un problema de arquitectura de la
suite, no se agregó un endpoint.

Tiene que pasar por las mismas defensas que el panel (validación de `Host`,
chequeo de origen para todo lo que cambie algo) y ser solo de lectura al
principio.

**Alertas por umbral** (idea 18). Más de N bloqueos por minuto, un pico de
consultas `TXT`, un dominio de malware nuevo. Reusando el `notifier.py` de
Telegram y el `desktop_alerts.py` de SecureProxy, que ya tienen resuelto el
silencio por dominio y el techo por hora. Sin eso, una herramienta que te tapa
la pantalla termina apagada, y apagada no avisa nada.

**Buscador con filtros** (idea 24). Filtrar por tipo, cliente, estado, motivo y
categoría. Es una mejora del buscador que ya existe, y recién tiene sentido
cuando existan las categorías (Fase 1) y las detecciones (Fase 2).

---

## Fase 5: el resumen

**Score de seguridad DNS** (idea 1) y **panel de inteligencia** (idea 25, en su
versión acotada al DNS).

Va último a propósito. Hoy un score sería un número calculado sobre nada: no
hay detección de tunneling, ni edad de dominio, ni DNSSEC, así que los puntos
saldrían de aire. Recién cuando existan las fases 2 y 3 hay de dónde sacarlos.

Y cuando se haga, la regla es que **cada punto sea trazable**: al lado de
"⚠ 4 dominios registrados hace poco" tiene que haber un link que te lleve a
esos 4. Un score que no se puede auditar es un adorno, y encima uno que da
falsa tranquilidad.

---

## Lo que no entra, y por qué

### Timeline tipo SIEM (idea 15)

**Es SecureCenter.** Un timeline vale cuando puede mezclar "el DNS resolvió
esto" con "el proxy abrió esa conexión" y "la VPN estaba caída". Con eventos de
una sola herramienta es un historial ordenado por fecha, que ya existe.

Si SecureDNS arma su propio timeline, cuando llegues a SecureCenter no vas a
tener nada que ponerle, y quien mire el portfolio va a ver dos paneles que
hacen lo mismo.

### Riesgo global de la red (parte de la idea 25)

Mismo motivo. "Riesgo de la red: 8/10" implica mirar las tres capas. SecureDNS
puede dar un score **de DNS** (Fase 5); el de la red es de SecureCenter.

### Mapa mundial de países (idea 13)

El país sí (Fase 3), el mapa no. El proyecto dibuja todos sus gráficos con
`div`s a propósito, sin librerías. Un mapa mundial son cientos de líneas de SVG
para mostrar lo mismo que una lista ordenada, y encima con menos precisión: en
un mapa no se lee "15.000 contra 900", se lee "dos manchas".

### Exportar a PCAP (parte de la idea 16)

**No se puede hacer con honestidad.** Un resolver no captura paquetes: guarda
filas en una base. Armar un `.pcap` a partir de esas filas sería fabricar un
archivo que dice ser una captura de red y no lo es. Si alguien lo abre en
Wireshark esperando el tráfico real, lo que ve es una reconstrucción inventada.

### Exportar a PDF (parte de la idea 16)

No por imposible, sino por dos razones: el informe de la red es de SecureCenter
(que tiene los datos de las tres), y generar PDF suma una dependencia pesada
para algo que el CSV ya resuelve.

### Elegir el upstream más rápido automáticamente (idea 6)

**Medir la latencia de cada upstream: sí. Cambiar solo: no**, o como mucho
apagado por defecto.

El motivo: Quad9 es el upstream primario **porque filtra malware por su
cuenta**, no porque sea el más rápido. Si el resolver se cambia solo a otro
porque respondió 8 ms antes, te bajó el nivel de filtrado sin avisarte. Y
sumar Google como tercer upstream, como sugería el ejemplo, contradice
directamente el motivo por el que el proyecto usa DNS-over-TLS: no querés que
tu proveedor de internet vea qué consultás, pero se lo estarías contando a
Google.

Una herramienta de seguridad no puede cambiar su postura de seguridad sola
para ganar milisegundos.

### "Categoría" y "reputación" del dominio (idea 4, en su forma original)

La versión de la propuesta ("Categoría: Business, Reputación: Excelente")
necesita un feed comercial pago. Sin fuente, esos dos campos serían inventados,
y un dato inventado en un panel de seguridad es peor que un campo vacío: alguien
lo va a creer.

La versión honesta (en qué lista apareció) sí entra, en la Fase 1.

### "HTTPS: sí" (parte de la idea 4)

Un resolver nunca ve eso. Para saber si un sitio habla HTTPS hay que
conectarse, y conectarse es la capa de SecureProxy. Pedírselo al DNS es pedirle
que adivine.

### Categorías "Adult" y "Fake Updates" (parte de la idea 21)

No tenemos listas para eso. Las categorías que van a aparecer son exactamente
las que salen de los feeds que ya se descargan. Inventar categorías vacías para
que el panel se vea más completo es el mismo problema del punto anterior.

---

## Resumen en una línea

Fase 1 mostrar lo que ya se guarda, Fase 2 el tunneling que es el verdadero
diferencial, Fase 3 la inteligencia externa con sus costos declarados, Fase 4
la API que le da sentido a SecureCenter, Fase 5 el score cuando haya de dónde
sacarlo.
