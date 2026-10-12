#!/bin/bash
# Compila e instala tsdecrypt (descifrador Newcamd en C con libdvbcsa).
#
# tsdecrypt es software GPL y se compila desde su repositorio. Necesita
# libdvbcsa y OpenSSL. Si apt no encuentra libdvbcsa se compila tambien.
set -e

echo "=== dependencias ==="
if ! dpkg -s libssl-dev >/dev/null 2>&1; then
    echo "instalando libssl-dev…"
    sudo -n apt-get install -y libssl-dev >/dev/null 2>&1 || echo "AVISO: no se pudo instalar libssl-dev"
fi

if ! ldconfig -p | grep -q libdvbcsa; then
    echo "libdvbcsa no esta; se compila desde el codigo"
    cd /tmp
    rm -rf libdvbcsa
    if curl -sSL -o dvbcsa.tar.gz https://get.cesbo.com/libdvbcsa/libdvbcsa-1.1.0.tar.gz 2>/dev/null && tar -xzf dvbcsa.tar.gz 2>/dev/null; then
        cd libdvbcsa-1.1.0 2>/dev/null || cd libdvbcsa*
        ./configure --prefix=/usr/local >/dev/null 2>&1 && make -j4 >/dev/null 2>&1 && sudo -n make install >/dev/null 2>&1
        sudo -n ldconfig || true
    else
        echo "AVISO: no se pudo descargar libdvbcsa"
    fi
fi

echo "=== compilando tsdecrypt ==="
cd /tmp
rm -rf tsdecrypt
if git clone -q --depth 1 https://github.com/gfto/tsdecrypt.git 2>/dev/null; then
    cd tsdecrypt
    make -j4 >/tmp/tsd-build.log 2>&1 || { echo "fallo el make:"; tail -15 /tmp/tsd-build.log; exit 1; }
    sudo -n install -m 0755 tsdecrypt /usr/local/bin/tsdecrypt
    echo "instalado en /usr/local/bin/tsdecrypt"
    tsdecrypt --help 2>&1 | head -4 || true
else
    echo "AVISO: no se pudo clonar el repositorio de tsdecrypt"
    exit 1
fi
