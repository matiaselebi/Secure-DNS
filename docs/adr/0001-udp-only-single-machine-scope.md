# ADR 0001: Alcance de una sola máquina, solo UDP entrante

## Estado

Aceptado.

## Contexto

Un resolver DNS "completo" para una red doméstica necesitaría escuchar en
todas las interfaces (no solo loopback), soportar TCP además de UDP para
respuestas grandes, y pensar en exponer el servicio a otros dispositivos de
la red. Ese es un problema bastante más grande (y con superficie de ataque
bastante mayor) que "filtrar las consultas DNS de esta PC".

## Decisión

SecureDNS escucha únicamente en `127.0.0.1` y solo UDP en el lado que
recibe consultas (hacia los upstreams sí se habla TCP+TLS, ver ADR
DoT). Es una decisión de alcance explícita, no una limitación técnica que
se planee resolver: el proyecto está pensado para reemplazar el DNS de una
sola máquina, no para ser el DNS de una red.

## Consecuencias

Simplifica enormemente el modelo de amenaza (no hay que pensar en quién más
en la red podría consultar este resolver) y el código (no hace falta
manejar fragmentación TCP en las consultas entrantes, aunque sí para las
salientes en modo DoT). La limitación - no sirve para toda una red - está
documentada explícitamente en el README ("Qué NO hace"), como un límite de
alcance del proyecto y no como algo pendiente.


---

## Revisión (agosto de 2026): el lado que escucha ya no es solo UDP

La parte de "solo UDP" de esta decisión se revirtió, y conviene dejar escrito
por qué, porque el razonamiento original no era descuidado: la enorme mayoría
de las consultas viajan por UDP y agregar TCP parecía complejidad sin uso.

Lo que faltaba mirar es qué pasa cuando una respuesta **no entra** en un
datagrama. En ese caso el servidor la manda truncada con el flag TC y el
cliente está obligado a reintentar por TCP en el mismo puerto. Sin nadie
escuchando ahí, esas consultas no se resuelven nunca: no fallan rápido, se
quedan colgadas hasta el timeout. Pasa con respuestas TXT largas, con cadenas
de CNAME y con registros de SPF o DKIM, o sea con cualquier cliente de correo.
Y lo exige el RFC 7766.

Desde entonces `ServidorDNS` levanta los dos, UDP y TCP, en el mismo puerto.

El resto de esta decisión (una sola máquina, `127.0.0.1`, no servir DNS a una
red de terceros) sigue en pie.
