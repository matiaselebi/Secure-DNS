# ADR 0004: la detección por comportamiento señala, no bloquea

**Estado:** aceptada
**Fecha:** agosto de 2026

## Contexto

SecureDNS bloquea por listas: un dominio está en un feed de amenazas o no lo
está. Eso funciona para lo conocido y no sirve para nada nuevo.

La Fase 2 suma dos detecciones que no miran listas sino la **forma** del
tráfico:

- **Tunneling por DNS.** Sacar datos de una red codificándolos en el nombre que
  se consulta y recibiendo la respuesta en un registro TXT. Funciona porque el
  DNS casi nunca está bloqueado, y es lo que usan varias familias de malware
  para exfiltrar datos y para hablar con su servidor de control.
- **Actividad fuera de lo normal.** Un equipo que multiplica por varias veces
  su ritmo habitual de consultas.

Esto es lo único de todo el proyecto que **solo un resolver puede ver**. El
proxy ve una conexión a un puerto; la VPN ve un túnel cifrado. El único que ve
los nombres consultados, uno por uno, es el DNS.

## Decisión

**Las detecciones marcan el hallazgo en el panel. No bloquean, no responden
NXDOMAIN, no cortan nada.**

Además:

1. **Hacen falta al menos dos señales coincidentes** para marcar un grupo. Cada
   señal por separado tiene explicaciones inocentes.
2. **Cada hallazgo muestra qué señales dieron y con qué números.** No hay un
   puntaje opaco.
3. **Los umbrales viven con nombre y con su motivo escrito** en
   `src/securedns/deteccion.py`, para que se puedan discutir sin leer el
   código.
4. **El filtro de ruido del panel no se aplica a las detecciones**, aunque esté
   prendido.

## Por qué

### Por qué no bloquear

Un detector estadístico tiene falsos positivos por definición. Un resolver que
corta por su cuenta en base a una sospecha te deja sin resolver nombres, y eso
no se siente como "el DNS bloqueó algo": se siente como que se cayó internet.
El costo de un falso positivo bloqueante es que la herramienta se apaga, y una
herramienta apagada no detecta nada.

Es la misma decisión que ya se tomó en SecureProxy para sus detectores de
comportamiento (ADR 0007 de ese proyecto). Que las dos herramientas de la suite
se comporten igual ante la misma clase de problema es parte del punto.

### Por qué dos señales y no una

Cada señal, sola, marca cosas legítimas:

| Señal | Qué la explica sin que haya un túnel |
|---|---|
| Muchos nombres distintos | Un CDN genera montones de subdominios |
| Nombres largos | Hay servicios con nombres largos |
| Alta entropía | Un hash o un identificador de sesión |
| Proporción alta de TXT | Verificación de dominio, SPF, DMARC |

Con una sola señal el panel se llena de ruido y se ignora. Con tres se escapan
los túneles que van despacio, que son justamente los que interesan. Dos es el
punto donde un CDN (una señal) no entra y un túnel real (tres o cuatro) sí.

Los tests de `tests/test_fase2.py` fijan esto: la mitad de ellos son casos que
**no** se tienen que marcar.

### Por qué se muestra el motivo

Un hallazgo que no se puede auditar no se puede discutir, y lo que no se puede
discutir termina ignorado. "Sospechoso: sí" no le sirve a nadie. En cambio
"482 nombres distintos sobre 500 consultas, entropía de 4,41 bits por carácter,
93% de las consultas son TXT" se puede mirar y decidir.

### Por qué el filtro de ruido no aplica acá

El filtro existe para que la telemetría no tape lo que importa. Que
justamente esconda una detección sería el peor resultado posible: el panel
estaría ocultando exactamente lo que se construyó para encontrar.

### Por qué la comparación es de cada equipo contra sí mismo

Una tele consulta muchísimo menos que una notebook. Un umbral fijo para todos
marcaría siempre a la misma máquina y nunca a la tele, que es justo el
dispositivo del que menos se sabe. Lo que interesa no es el volumen absoluto
sino el cambio.

Se usa la **mediana** de las horas anteriores y no el promedio: con promedio,
un pico previo arrastra la base hacia arriba y esconde el pico siguiente.

Hay un piso absoluto (`MINIMO_PARA_AVISAR`) porque pasar de 2 consultas por
hora a 40 es veinte veces la base y no es una anomalía: es un equipo que se
prendió.

### Por qué el dominio padre se guarda calculado

La detección agrupa por `(equipo, dominio padre)`. Derivar el padre en cada
consulta convertiría cada refresco del panel en un scan completo de la tabla,
porque SQLite no puede indexar una expresión. Se guarda en una columna al
registrar, y hay un `recalcular_padres()` que completa las filas de una base
que ya existía.

El cálculo del padre usa una heurística y no la lista pública de sufijos: dos
etiquetas, o tres cuando la anteúltima es un segundo nivel conocido y el TLD
tiene dos letras. Eso cubre `com.ar`, `com.br`, `co.uk` y compañía. Sin eso,
"las dos últimas etiquetas" de `ejemplo.com.ar` daría `com.ar` y **todos** los
sitios argentinos quedarían agrupados bajo un mismo padre, que sería un falso
positivo enorme. La lista pública completa tiene miles de entradas y hay que
mantenerla actualizada: es una dependencia externa que no se justifica para
agrupar.

### Por qué hay un cache de un minuto

Medido sobre 200.000 filas, las dos detecciones juntas tardan unos 700 ms. El
panel se refresca cada 5 segundos, así que sin cache el proceso se pasaría el
14% del tiempo recalculando lo mismo, y con varias pestañas abiertas se
multiplica. La ventana que miran es de 24 horas: un minuto de desfasaje no
cambia nada, porque lo que se detecta son patrones de horas.

El cache vive en la clase del servidor y no en la clase base, para que dos
resolvers en el mismo proceso no se muestren los hallazgos del otro.

## Consecuencias

- El panel puede mostrar un hallazgo que resulte ser legítimo. Es el precio de
  detectar algo que ninguna lista conoce, y por eso cada hallazgo viene con sus
  motivos y con un botón para ver las consultas que lo generaron.
- Un túnel que vaya muy despacio, con pocas consultas por hora, no va a llegar
  al mínimo de volumen y no se va a marcar. Es una limitación consciente: bajar
  ese mínimo llenaría el panel de ruido.
- Los umbrales están calibrados a ojo sobre casos construidos, no sobre tráfico
  real medido durante semanas. Están todos con nombre en un solo archivo para
  poder ajustarlos cuando haya datos de uso.
