# El resolutor propio: qué fue, qué enseñó y dónde queda

Desde la fase 4, SecureDNS puede correr sin resolver nada: el que resuelve es
Pi-hole y SecureDNS le publica listas, le importa consultas y les corre encima
la detección. Este documento es sobre el código que dejó de estar en el camino
de cada consulta.

**No se borra.** Sigue en el repositorio, sigue teniendo sus 16 tests, y sigue
funcionando con `dns.modo: "propio"`. Lo que cambió es que dejó de ser
obligatorio.

## Qué es la plomería

Son 669 líneas en `src/securedns/dns_server.py`, más 539 líneas de tests en
`tests/test_dns_server.py` y `tests/test_dot.py`:

- el servidor UDP en el puerto 53 y el manejo de sockets;
- el cliente de DNS-over-TLS, con validación del nombre del certificado;
- la caché de respuestas con TTL mínimo;
- la lógica de upstream primario, respaldo y caída a UDP plano;
- las tres formas de contestar un dominio bloqueado (NXDOMAIN, 0.0.0.0,
  127.0.0.1).

## Por qué se jubila

Porque mantener un servidor DNS es un trabajo que no termina nunca (tipos de
registro nuevos, casos raros de EDNS, cambios en los upstream, seguridad) y
ese trabajo no es lo que hace valioso a este proyecto. Lo valioso es lo que
está arriba: la detección de túneles por comportamiento, las categorías, los
hallazgos marcados como normales y el puntaje. Nada de eso necesitaba que el
resolutor fuera propio, y desde la fase 3 corre sobre las consultas de Pi-hole
sin que se le tocara una línea.

## Por qué igual vale la pena tenerlo

Es el código que más enseñó de todo el proyecto, y es el que mejor se cuenta:

- **Que un resolutor es un traductor con estado.** La caché no es una
  optimización opcional: sin ella, cada página web dispara decenas de
  consultas idénticas.
- **Que DoT no es "poner TLS".** Si no se valida el nombre del certificado
  contra el esperado, cualquiera que pueda interceptar el puerto 853 responde
  lo que quiera y el cifrado no sirvió de nada. Eso está en el código y está
  en un test.
- **Que fallar abierto o cerrado es una decisión, no un accidente.**
  `dot_fallback_to_udp` es literalmente esa decisión escrita: priorizar que
  internet funcione, o priorizar que nada salga sin cifrar. Las dos son
  defendibles; lo indefendible es no saber cuál elegiste.
- **Que cómo se contesta un bloqueo cambia lo que ve el usuario.** NXDOMAIN
  da un error rápido; 0.0.0.0 da una espera larga. Es la diferencia entre una
  página que falla y una que se cuelga.

## Cómo guardarlo como rama archivada

Cuando se cumplan los criterios de jubilación (ver el ADR 0007) y se decida
sacarlo de `main`, el código no se tira: se etiqueta.

    git checkout -b archivo/resolutor-propio
    git push -u origin archivo/resolutor-propio
    git tag -a v-resolutor-propio -m "Ultimo estado del resolutor DNS propio"
    git push origin v-resolutor-propio
    git checkout main

Y recién ahí, en `main`:

    git rm src/securedns/dns_server.py tests/test_dns_server.py tests/test_dot.py

La rama queda enlazada desde el README, que es donde alguien que mira el
repositorio la va a encontrar.

## Lo que NO hay que hacer

Borrarlo antes de que Pi-hole tenga tiempo de rodaje en la red real. El modo
`propio` es la vuelta atrás: mientras exista, un problema con Pi-hole se
resuelve cambiando una línea del config. Sin él, se resuelve recuperando
código de una rama a las tres de la mañana.
