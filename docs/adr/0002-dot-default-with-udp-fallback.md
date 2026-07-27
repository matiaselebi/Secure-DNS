# ADR 0002: DNS-over-TLS (DoT) por defecto, con fallback a UDP configurable

## Estado

Aceptado.

## Contexto

Las consultas DNS en texto plano por UDP (puerto 53) son legibles por
cualquiera en el camino de red: el ISP, un router comprometido, alguien en
la misma red WiFi. Cifrar esa consulta (DNS-over-TLS o DNS-over-HTTPS)
resuelve ese problema puntual, a costa de una conexión TCP+TLS persistente
por upstream en vez de un datagrama UDP suelto por consulta.

Se evaluaron dos protocolos: DoT (puerto 853 dedicado, más simple de
distinguir/permitir en un firewall) y DoH (camuflado dentro de HTTPS normal,
puerto 443, más difícil de bloquear pero también más difícil de auditar
como administrador de la propia red). Se eligió DoT por su simplicidad de
implementación (solo `ssl` + `socket` de la librería estándar, sin
dependencias HTTP adicionales) y porque el escenario de amenaza principal
acá es el ISP/red local, no un firewall corporativo intentando bloquear
DNS cifrado específicamente.

## Decisión

`upstream_mode: "dot"` es el default. Si ningún upstream responde por TLS
(puerto 853 bloqueado en esa red - pasa en universidades, cafés, redes
corporativas), `dot_fallback_to_udp: true` (default) permite caer
automáticamente a UDP en texto plano para no perder conectividad. Se puede
poner en `false` para modo "privacidad estricta": si TLS no funciona,
responde `SERVFAIL` en vez de consultar sin cifrar.

## Consecuencias

Por defecto se prioriza que internet siga funcionando en cualquier red por
sobre la privacidad estricta - una decisión consciente para un proyecto de
uso personal donde quedarse sin DNS es más disruptivo que perder cifrado
puntualmente en una red restrictiva. Quien prefiera lo contrario puede
invertir esa prioridad con un solo valor de configuración.
