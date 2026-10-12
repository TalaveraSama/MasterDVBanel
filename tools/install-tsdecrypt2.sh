#!/bin/bash
# Compila tsdecrypt trayendo sus submodulos (libfuncs, FFdecsa, libdvbcsa).
set -e

cd /tmp
rm -rf tsdecrypt
echo "=== clonando con submodulos ==="
if ! git clone -q --depth 1 --recursive https://github.com/gfto/tsdecrypt.git 2>&1; then
    git clone -q https://github.com/gfto/tsdecrypt.git
    cd tsdecrypt
    git submodule update --init --recursive 2>&1 | tail -5
else
    cd tsdecrypt
    git submodule update --init --recursive 2>&1 | tail -5 || true
fi

echo "=== contenido de libfuncs ==="
ls libfuncs 2>/dev/null | head -8 || echo "(no existe libfuncs)"

echo "=== libdvbcsa ==="
if [ -d libdvbcsa ]; then
    cd libdvbcsa
    if [ ! -f libdvbcsa.so ] && [ ! -f src/.libs/libdvbcsa.so ]; then
        ./configure --prefix=/usr/local >/dev/null 2>&1 || autoreconf -i >/dev/null 2>&1 || true
        make -j4 >/dev/null 2>&1 || true
    fi
    ls src/.libs/*.so* 2>/dev/null | head -3 || echo "(sin .so construido)"
    cd ..
fi

echo "=== compilando tsdecrypt ==="
if [ -f configure ]; then ./configure >/dev/null 2>&1 || true; fi
make -j4 >/tmp/tsd-build.log 2>&1 || { echo "fallo el make:"; tail -12 /tmp/tsd-build.log; exit 1; }
sudo -n install -m 0755 tsdecrypt /usr/local/bin/tsdecrypt
echo "instalado: $(which tsdecrypt)"
tsdecrypt --help 2>&1 | head -3 || true
