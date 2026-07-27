# ADR 0003: Bloqueo de ads/trackers como categoría opcional separada

## Estado

Aceptado.

## Contexto

Bloquear dominios de publicidad y tracking (feeds tipo StevenBlack/hosts)
es una funcionalidad muy pedida en resolvers DNS caseros, pero es
categóricamente distinta de bloquear amenazas activas (malware, phishing,
C2 de botnets): un dominio de tracking no es malicioso en el sentido de
"te va a infectar", y bloquearlo puede romper visualmente algún sitio que
dependa de él para cargar contenido.

## Decisión

Se agregó como una lista y un feed completamente separados
(`data/blocklist_adtracker.txt`, alimentado por
`scripts/update_blocklist.py --include-ad-tracker` / la config
`filtering.enable_ad_tracker_blocklist`), desactivada por defecto. Al
activarla, se combina con la blocklist de seguridad de la misma forma que
la lista manual y la de feeds (`Blocklist` ya soporta múltiples archivos),
pero como un archivo aparte para que se pueda auditar o desactivar sin
tocar la blocklist de amenazas.

## Consecuencias

Quien solo quiere protección contra amenazas activas no ve cambiado su
comportamiento (default `false`). Quien también quiere bloquear
publicidad/tracking lo activa con una sola línea de configuración, sin que
esa lista se mezcle ni se confunda con la de amenazas reales en los logs o
el dashboard.
