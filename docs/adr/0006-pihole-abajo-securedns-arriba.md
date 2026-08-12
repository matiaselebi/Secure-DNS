# ADR 0006: Pi-hole resuelve, SecureDNS decide qué bloquear

Fecha: 2026-08-09
Estado: aceptada (fase 1 de cuatro)

## Contexto

SecureDNS tiene un resolutor propio: escucha en el 53, arma la consulta, la
manda por DoT, cachea, y filtra contra sus listas. Anda y está probado. El
problema no es que funcione mal, es que hay que mantenerlo para siempre, y
mantener un servidor DNS es un trabajo que no termina nunca: formatos de
registro nuevos, casos raros de EDNS, cambios en los upstream, seguridad.

Ese trabajo no es lo que hace valioso a este proyecto. Lo que lo hace valioso
es lo que está arriba del resolutor: la detección de túneles DNS por
comportamiento, las categorías, el marcado de hallazgos como normales, el
puntaje de la red y el panel. Nada de eso depende de que el resolutor sea
nuestro.

Pi-hole hace lo de abajo, lo hace bien, tiene años de rodaje y se actualiza
solo.

## Decisión

Pi-hole pasa a ser el resolutor. SecureDNS pasa a ser la capa de arriba: le
publica las listas que junta Secure-Intel y le lee las consultas.

**A Pi-hole se le habla por su API REST y por ninguna otra puerta.** En
concreto: `POST /api/auth` para abrir sesión, `GET`/`POST /api/lists` para las
adlists y `POST /api/action/gravity` para reconstruir.

## Por qué NO se escribe en gravity.db

Es lo que hace la mayoría de las integraciones que uno encuentra dando
vueltas, y funciona hoy. Se descarta igual, por tres motivos:

1. `gravity.db` es una base **interna** de Pi-hole. Su esquema no es un
   contrato con nadie y cambia entre versiones mayores.
2. El propio `pihole -g` la reconstruye. Lo que metas a mano puede
   desaparecer sin un solo mensaje de error.
3. Todo el sentido de poner Pi-hole abajo era dejar de mantener plomería. Una
   integración que se rompe con cada actualización cambia un mantenimiento por
   otro, y encima por uno que falla en silencio.

## Consecuencias

**A favor.** Se deja de mantener un servidor DNS. Pi-hole resuelve para toda
la casa, no solo para una máquina, así que las listas y las consultas pasan a
cubrir todos los dispositivos. La integración sobrevive a las actualizaciones
de Pi-hole mientras su API pública no cambie.

**En contra.** Aparece una dependencia de que Pi-hole esté vivo y de que su
API siga siendo la misma. Hay que administrar una contraseña más, que vive en
el `.env`. Y `file://` como origen de la lista obliga a que SecureDNS corra en
la misma máquina que Pi-hole; si no, hay que servir la lista por HTTP.

**Lo que no cambia.** El resolutor propio no se borra: sigue en el repositorio
y funciona. Con `pihole.habilitado: false`, que es el valor por defecto,
SecureDNS se comporta exactamente como antes. Recién en la fase 4 la plomería
del resolutor sale a una rama archivada.

## Las guardas que van con esta decisión

Publicar una lista es decirle a un programa que obedece sin preguntar qué
tiene que bloquear para toda la casa. Por eso el publicador se niega a:

- publicar una lista **vacía** (dejaría de bloquear todo, sin un solo error);
- publicar una lista que **encogió a menos de la mitad** de la anterior (es la
  misma guarda que ya usa Secure-Intel al bajar un feed);
- correr `gravity` **si el archivo no cambió** (reconstruir el árbol cuesta
  minutos de CPU y no cambiaría nada).

## Fases

1. **Publicar las listas.** Hecho. `pihole_api.py` y `publicador.py`.
2. **Leer sus consultas.** Hecho. Un adaptador nuevo en SecureCenter
   (`_pihole` en `adaptadores.py`) que abre `pihole-FTL.db` en `mode=ro` y
   traduce los bloqueos al modelo de evento común. Desde ahí, las tres reglas
   de correlación ya lo están mirando, y por primera vez con el **equipo** de
   la casa que preguntó.
3. **Salvar lo propio.** Hecho. `pihole_consultas.py` trae las consultas de
   Pi-hole a la tabla `queries` de SecureDNS, enriquecidas con el dominio
   padre precalculado, la categoría cruzada contra nuestras listas y la marca
   de ruido. `deteccion.py`, `hallazgos.py` y `puntaje.py` **no cambiaron ni
   una línea** y ahora corren sobre el tráfico de toda la casa.
4. Jubilar la plomería del resolutor a una rama archivada. Pendiente.

### El doble conteo, que es lo que hay que mirar al tocar esto

Las fases 2 y 3 leen la misma fuente por dos caminos: SecureCenter lee
`pihole-FTL.db` directo, y SecureDNS importa esas mismas consultas a su propia
base, que SecureCenter también lee. Sin una marca, cada bloqueo entraría dos
veces y el correlacionador creería ver dos herramientas distintas donde hay
una sola.

La marca es la columna `origen` de `queries`: las filas importadas quedan como
`'pihole'` y el adaptador de SecureDNS las excluye. Los dos caminos existen a
propósito y no se pisan: el de SecureCenter funciona aunque SecureDNS esté
apagado, y el de SecureDNS es el que alimenta la detección de túneles.

### Por qué se copian las consultas en vez de consultarlas donde están

Porque no es una copia, es un enriquecido. A cada fila se le agrega lo que
Pi-hole no tiene: el dominio padre precalculado (sin él, la detección de
túneles hace un scan completo en cada refresco del panel), la categoría según
nuestras listas (Pi-hole sabe que bloqueó, no sabe si fue malware o
publicidad, porque gravity mezcla todas las listas en una bolsa) y la marca de
ruido. Además Pi-hole poda su historial con su propio criterio, y lo ya
importado sobrevive a esa poda.

## Referencias

- Autenticación de la API de Pi-hole: <https://docs.pi-hole.net/api/auth/>
- `type` va en la query string y no en el cuerpo al agregar una lista:
  <https://github.com/NixOS/nixpkgs/issues/500852>
- `gravity` devuelve texto en vivo con códigos ANSI:
  <https://github.com/pi-hole/FTL/issues/2671>
- Permisos de los archivos locales usados como adlist:
  <https://github.com/pi-hole/pi-hole/pull/6430>
