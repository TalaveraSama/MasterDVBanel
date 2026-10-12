#!/bin/bash
# Prueba tsdecrypt contra el OSCam del host (newcamd 5000, usuario astra).
#
# tsdecrypt lee el TS del sintonizador, pide el ECM a OSCam y descifra con
# FFdecsa/libdvbcsa. Aqui se comprueba que el login y el ECM funcionan.
set -u

echo "=== tsdecrypt contra OSCam (newcamd 127.0.0.1:5000) ==="
echo "usuario: astra / astra, deskey 0102030405060708091011121314"
echo

# Salida a fichero para poder comprobar que llega TS
SALIDA=/tmp/tsd-prueba.ts
rm -f "$SALIDA"

timeout 25 tsdecrypt \
    -d 0 -f 0 \
    -s 127.0.0.1:5000 \
    -u astra -p astra \
    -k 0102030405060708091011121314 \
    -c 1802:000000 \
    -i 8 \
    -O file://"$SALIDA" \
    -t 4 \
    -v 2>&1 | head -30

echo
echo "=== resultado ==="
if [ -f "$SALIDA" ]; then
    echo "salida creada: $(stat -c%s "$SALIDA") bytes"
else
    echo "no se creo la salida"
fi
