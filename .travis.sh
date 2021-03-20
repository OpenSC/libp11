#!/bin/sh
set -e
#
# Copyright (c) 2016 Michał Trojnara <Michal.Trojnara@stunnel.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

fetch_from_github() {
    git clone https://github.com/$1/$2.git -b $3 --depth=1
}

install_from_github() {
    echo "Installing $2"
    fetch_from_github $1 $2 $3
    cd $2
    autoreconf -fvi
    ./configure $4 $5
    make
    sudo -E make install
    cd ..
    echo "$2 installed"
    if [ $TRAVIS_OS_NAME != 'osx' ]; then
        sudo ldconfig
    fi
}

install_openssl() {
    echo "Installing $1"
    fetch_from_github openssl openssl $1
    cd openssl
    OPENSSL_DIR=/usr/local

    if [ $TRAVIS_OS_NAME == 'osx' ]; then
        # To compile x86_64 version it is required to call
        # './Configure darwin64-x86_64-cc' manually
        ./Configure darwin64-x86_64-cc shared -fPIC \
            --openssldir=${OPENSSL_DIR} --prefix=${OPENSSL_DIR}
    else
        ./config shared -fPIC --openssldir=${OPENSSL_DIR} --prefix=${OPENSSL_DIR}
    fi
    make depend && make
    sudo make install_sw
    cd ..
    echo "$1 installed"
    if [ $TRAVIS_OS_NAME != 'osx' ]; then
        sudo ldconfig
    fi
    SOFTHSM_OPENSSL_DIR="--with-openssl=${OPENSSL_DIR}"
}

if [ $TRAVIS_OS_NAME = 'osx' ]; then
    brew update
    brew install pcsc-lite
    brew link --force pcsc-lite
else
    sudo apt-get update -qq

    # libpcsclite-dev is required for OpenSC
    sudo apt-get install -y libpcsclite-dev
fi

export CC=`which $CC`
mkdir prerequisites
cd prerequisites

if [ -n "${OPENSSL}" ]; then

    if [ $TRAVIS_OS_NAME != 'osx' ]; then
        # Remove pre-installed OpenSSL
        sudo apt-get remove openssl libssl-dev
    fi

    install_openssl ${OPENSSL}
fi

# sometimes git master has compile warnings in it
install_from_github OpenSC OpenSC master --disable-strict

# softhsm is required for "make check"
install_from_github opendnssec SoftHSMv2 master --disable-gost \
    ${SOFTHSM_OPENSSL_DIR}

cd ..
rm -rf prerequisites
