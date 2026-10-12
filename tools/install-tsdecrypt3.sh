#!/bin/bash
# tsdecrypt con los submodulos apuntados a GitHub (el servidor original cayo).
#
#   libfuncs    -> https://github.com/gfto/libfuncs
#   libtsfuncs  -> https://github.com/gprj/libtsfuncs
set -e

cd /tmp
rm -rf tsdecrypt
echo "=== clonando tsdecrypt ==="
git clone -q --depth 1 https://github.com/gfto/tsdecrypt.git
cd tsdecrypt

echo "=== submodulos desde GitHub ==="
rm -rf libfuncs libtsfuncs
git clone -q --depth 1 https://github.com/gfto/libfuncs.git libfuncs 2>/dev/null \
    || git clone -q --depth 1 https://github.com/gprj/libfuncs.git libfuncs 2>/dev/null \
    || echo "AVISO: no se pudo clonar libfuncs"
git clone -q --depth 1 https://github.com/gprj/libtsfuncs.git libtsfuncs 2>/dev/null \
    || git clone -q --depth 1 https://github.com/gfto/libtsfuncs.git libtsfuncs 2>/dev/null \
    || echo "AVISO: no se pudo clonar libtsfuncs"

ls -d libfuncs libtsfuncs 2>/dev/null || true
echo "=== compilando ==="
make -j4 >/tmp/tsd-build.log 2>&1 || { echo "fallo el make:"; tail -14 /tmp/tsd-build.log; exit 1; }
sudo -n install -m 0755 tsdecrypt /usr/local/bin/tsdecrypt
echo "instalado: $(command -v tsdecrypt)"
tsdecrypt --help 2>&1 | head -4 || true
