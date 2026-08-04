# ADR 0005: la API es de solo lectura y sin CORS

**Estado:** aceptada
**Fecha:** agosto de 2026

## Contexto

Las tres herramientas de la suite (SecureProxy, SecureDNS, SecureVPN) se
supone que se miran juntas desde SecureCenter. Pero hasta ahora **no hay
ningún contrato entre ellas**: cada una expone un panel HTML y nada más.

Eso deja a SecureCenter con una sola opción, que es raspar el HTML de cada
panel. Un raspador se rompe con cada cambio de diseño, y el diseño de estos
paneles cambia seguido. O sea que la integración estaría rota la mitad del
tiempo, y nadie sabría por qué.

## Decisión

SecureDNS expone una API HTTP bajo `/api/`, con estas reglas:

1. **Solo lectura.** No hay ningún endpoint que cambie algo.
2. **Sin `Access-Control-Allow-Origin`.**
3. **Mismo chequeo de `Host` que el panel.**
4. **Sin token ni autenticación.**
5. **Todos los parámetros numéricos tienen tope.**
6. **`Cache-Control: no-store`** en todas las respuestas.

La idea es que esta misma forma se porte después a SecureProxy y a SecureVPN,
así SecureCenter habla igual con las tres.

## Por qué

### Por qué solo lectura, y por qué eso permite no tener token

Son la misma decisión mirada de dos lados.

Una API que además escribiera necesitaría autenticación de verdad: si algo
puede cambiarte el modo de upstream o meterte un dominio en la lista blanca,
tiene que probar quién es. Y montar un esquema de tokens en un servicio que
escucha en `127.0.0.1` agrega bastante superficie (dónde se guarda el token,
cómo se rota, qué pasa si se filtra en un log) para resolver un problema que
el panel ya tiene resuelto de otra forma.

Como es solo lectura, alcanza con las dos defensas que ya existen: el chequeo
de `Host`, que frena el DNS rebinding, y la ausencia de CORS, que impide que
otra página lea las respuestas. Todo lo que cambia algo sigue en el panel,
detrás del chequeo anti-CSRF.

### Por qué NO se manda CORS

Es el punto que más fácil se hace mal, porque `Access-Control-Allow-Origin: *`
es lo primero que uno agrega cuando algo "no anda" desde el navegador.

Sin ese header, el navegador deja que otra página HAGA el pedido pero no que
LEA la respuesta. Agregándolo, cualquier sitio que visites podría leer
`/api/historial` y llevarse **el historial de DNS de toda la casa**: cada
nombre que consultó cada dispositivo. Es una de las cosas más sensibles que
guarda este proyecto.

SecureCenter no lo necesita: no es una página web en un navegador, es un
proceso que hace pedidos HTTP, y a un proceso CORS no le aplica.

### Por qué los topes en los parámetros

`/api/historial?limite=99999999` sin tope traería la tabla entera a memoria
para armar un JSON de cientos de MB. No hace falta mala intención: alcanza con
que alguien pruebe qué pasa. Todos los parámetros numéricos se acotan a un
máximo razonable y un valor que no sea número cae en el default en vez de
tirar una excepción.

### Por qué `no-store`

Un intermediario o el propio navegador guardando el historial de DNS en disco
es exactamente el tipo de filtración silenciosa que uno no descubre nunca.

### Por qué en el mismo puerto que el panel

Un puerto más es un socket más que escucha, una regla más de firewall, un
parámetro más de configuración, y una cosa más que puede quedar expuesta sin
querer. Como comparten las mismas defensas y el mismo proceso, separarlos
sería más superficie sin ninguna ganancia.

## Consecuencias

- SecureCenter puede leer el estado de SecureDNS sin raspar HTML, y el panel
  puede cambiar de diseño sin romper la integración.
- Si en algún momento hace falta que SecureCenter **actúe** sobre las
  herramientas (apagar el resolver, agregar un dominio), esta decisión hay que
  revisarla, y ahí sí va a hacer falta autenticación. La API de hoy no se
  puede extender a escritura sin volver a este documento.
- Los tests de `tests/test_fase4.py` fijan las reglas que son fáciles de
  romper sin darse cuenta: que no aparezca CORS, que el `Host` se chequee, que
  los topes se apliquen y que un recurso inventado devuelva 404 diciendo
  cuáles existen.
