# ADR 0007: el resolutor propio se jubila, pero no se borra todavía

Fecha: 2026-08-09
Estado: aceptada (fase 4 del ADR 0006)

## Contexto

Las fases 1, 2 y 3 dejaron todo lo necesario para que Pi-hole resuelva y
SecureDNS analice: se le publican las listas, se le leen las consultas y la
detección corre sobre ellas sin que se le tocara una línea. Lo único que
quedaba era que SecureDNS dejara efectivamente de resolver.

## Decisión

Se agrega `dns.modo` con tres valores: `propio`, `pihole` y `auto` (el de
fábrica, que elige Pi-hole si está habilitado). En modo Pi-hole, SecureDNS
**no abre el puerto 53 y no toca el DNS del sistema**: levanta el panel,
publica las listas cada tantas horas e importa las consultas cada pocos
minutos.

**El resolutor no se borra en esta ADR.** Sigue en el repositorio, con sus
tests, y se enciende cambiando una línea del config.

## Por qué no se borra ahora

Por la regla 9 de la hoja de ruta: cada motor entra con el camino viejo
todavía funcionando, hasta que el nuevo esté probado. Pi-hole todavía no
corrió un solo día en la red real: el servidor de Debian no está armado. Un
`git rm` hoy no demuestra nada y convierte cualquier problema de Pi-hole en
una recuperación de código en vez de un cambio de una línea.

## La decisión que se centraliza, y por qué es la parte importante

"Quién resuelve" cambia el comportamiento de cinco lugares: si se abre el 53,
si se toca el DNS del sistema, qué levanta el punto de entrada, qué muestra el
panel, y qué le pide SecureCenter al adaptador de red. Con un `if` en cada
uno, alcanza con olvidarse de uno para provocar la peor falla de todas: **el
sistema apuntando a un resolutor que no está escuchando**, que es quedarse sin
internet sin ningún mensaje de error.

Este proyecto ya tuvo ese apagón una vez, por tener el mismo PowerShell
escrito en dos lados. Por eso la respuesta se calcula en `modo.py` y nadie más
la deduce:

- `run_dns.py` pregunta antes de construir el resolutor.
- `net_config.tomar_el_dns_si_corresponde()` pregunta antes de tocar el
  adaptador, y es la puerta que usa SecureCenter.
- `stop_dns.py` pregunta antes de restaurar algo que quizás nunca cambió.
- Hay un test que recorre el paquete y falla si aparece otra comparación
  contra `cfg.dns.modo` fuera de `modo.py`.

## La contradicción que se ataja

`modo: "pihole"` con `pihole.habilitado: false` es pedir que resuelva alguien
que no está configurado. Se avisa fuerte y se vuelve a `propio`, que es el
único de los dos que puede funcionar solo. Se falla hacia el lado que sigue
resolviendo nombres.

## Honestidad del panel

En modo Pi-hole el resolutor no se construye. Si se construyera, el panel
mostraría una caché con entradas y un upstream configurado que no está
atendiendo ni una consulta, y eso rompe la regla 10: nada dice que está
protegiendo si no lo está. En su lugar hay un objeto que contesta caché cero,
y el arranque imprime explícitamente qué **no** aplica en este modo.

## Criterios para borrarlo de verdad

Se saca de `main` (siguiendo los pasos de `docs/ARCHIVO-resolutor.md`) recién
cuando se cumplan las cuatro cosas:

1. Pi-hole resolviendo para la red real, sin volver a modo propio, durante al
   menos dos semanas seguidas.
2. La publicación de listas corriendo sin errores en ese período, con al menos
   un `gravity` disparado por un cambio real de las listas.
3. La importación de consultas al día, con la marca de agua avanzando y sin
   estados desconocidos acumulados.
4. La pestaña Detección mostrando grupos con la IP de más de un equipo de la
   casa, que es la prueba de que lo importado sirve para lo que se importó.

Mientras alguna falte, el resolutor se queda donde está.

## Consecuencias

**A favor.** Deja de haber un servidor DNS propio en el camino de cada
consulta de la casa. El código que más enseñó queda documentado y accesible en
vez de escondido. La vuelta atrás es una línea del config.

**En contra.** Durante un tiempo conviven dos caminos, y eso es superficie que
hay que probar en los dos modos. Es un costo aceptado: es más barato que un
apagón de DNS.
