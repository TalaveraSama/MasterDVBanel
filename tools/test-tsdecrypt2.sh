#!/bin/bash
# Prueba tsdecrypt contra OSCam usando el nombre del sistema CA.
#
#   -c SECA    sistema (Mediaguard/SECA; el CAID 1802 es SECA)
#   -C 1802    CAID explicito
#   -v         solo ECM (no decodifica): sirve para ver si el CAM responde
#
# Se prueba tambien el sintonizador real para comprobar que llega el ECM.
set -u

COMUN="-s 127.0.0.1:5000 -u astra -p astra -k 0102030405060708091011121314 -C 1802"

echo "=== 1) ECM solo, sin sintonizador (comprueba el CAM) ==="
timeout 20 tsdecrypt -c SECA $COMUN -v -H 3 -t 3 2>&1 | head -20

echo
echo "=== 2) Con sintonizador y salida a fichero ==="
rm -f /tmp/tsd-prueba.ts
timeout 25 tsdecrypt -d 0 -f 0 -c SECA $COMUN -H 5 -t 4 \
    -O file:///tmp/tsd-prueba.ts 2>&1 | head -25
echo
if [ -f /tmp/tsd-prueba.ts ]; then
    echo "salida: $(stat -c%s /tmp/tsd-prueba.ts) bytes"
else
    echo "sin salida"
fi
