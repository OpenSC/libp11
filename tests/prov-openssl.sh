#!/bin/bash

export OPENSSL_MODULES=../src/.libs
export OPENSSL_CONF=./openssl.conf
export OPENSSL_CONF_NO_DIGEST=./openssl_no_digest.conf

RED='\033[7;31m'
GREEN='\033[0;32m'
NC='\033[0m'

print_result() {
    if [ ! -z "$1" ]; then
        [ $1 -eq 0 ] && echo -e $GREEN"OK"$NC || echo -e $RED"FAILED"$NC
        echo
    fi
}

print_variable() {
    echo $1"="`eval echo \\${$1}`
}

OPENSSL_VERSION=`openssl version | cut -d\  -f2`

echo "Openssl version: $OPENSSL_VERSION"

if [[ ! $OPENSSL_VERSION =~ 3.* ]]; then
    echo "This script requires openssl 3"
    exit 1
fi

if [ -z "$NO_LEGACY_CHECK" -a ! -f $OPENSSL_MODULES/legacy.so ]; then
    echo "Opencryptoki uses OpenSSL and needs the legacy provider. Some other tools may work similarly."
    echo "In case you face issues because of the missing legacy provider, please make sure that the"
    echo "legacy provider's shared library also available in $OPENSSL_MODULES"
    echo
    echo "To dismiss this warning, export NO_LEGACY_CHECK=1"
    echo
fi

echo "Please create an RSA and an EC key pair on your smartcard/HSM"
echo "Then update the key pair URIs in this script"
echo

PKCS11URI_RSA="pkcs11:token=utl;id=%01"
PKCS11URI_EC="pkcs11:token=utl;id=%02"
#PKCS11URI_RSA_NEWPAIR="pkcs11:token=utl;id=%03"

print_variable PKCS11URI_RSA
print_variable PKCS11URI_EC
echo

echo "=================================="
echo "check if provider loaded correctly"
openssl list -provider pkcs11prov -providers
print_result $?

echo "=================================="
echo "make a hash"
openssl dgst -provider pkcs11prov -sha256 ./data.txt
print_result $?

## No KDF supported yet
#echo "=================================="
#echo "make key derivation"
#openssl kdf -provider pkcs11prov -keylen 32 -kdfopt digest:SHA256 -kdfopt pass:password -kdfopt salt:salt -kdfopt iter:2 PBKDF2
#print_result $?

echo "=================================="
echo "cipher encrypt"
openssl aes-256-cbc -provider pkcs11prov -pass pass:1111 -salt -in data.txt -out data.txt.cipher.encrypt
print_result $?

echo "=================================="
echo "cipher decrypt"
openssl aes-256-cbc -provider pkcs11prov -pass pass:1111 -d -salt -in data.txt.cipher.encrypt -out data.txt.cipher.decrypt

# OK if we can decrypt without pkcs11 AND the resulting file is the same
openssl aes-256-cbc -provider default -pass pass:1111 -d -salt -in data.txt.cipher.encrypt -out data.txt.cipher.no_pkcs11.decrypt
cmp data.txt.cipher.decrypt data.txt.cipher.no_pkcs11.decrypt
print_result $?

echo "=================================="
echo "cipher with PBKDF2 test"
# Note 1: KDF not yet supported, hence "-provider default" required to provide the PBKDF2 algorithm
# Note 2: OpenSSL implementation of PBKDF2 requires digest session state saving (it duplicates session after some date sent into),
#         but Opencryptoki SW implementation does not support session state saving with OpenSSL3, hence digest disabled in these
#         samples, with using another OpenSSL config 
#
OPENSSL_CONF=$OPENSSL_CONF_NO_DIGEST openssl aes-256-cbc -provider pkcs11prov -provider default -pass pass:1111 -nosalt -pbkdf2 -in data.txt -out data.txt.cipher.pbkdf2.encrypt
OPENSSL_CONF=$OPENSSL_CONF_NO_DIGEST openssl aes-256-cbc -provider pkcs11prov -provider default -pass pass:1111 -d -nosalt -pbkdf2 -in data.txt.cipher.pbkdf2.encrypt -out data.txt.cipher.pbkdf2.decrypt
# Try to decrypt without provider and check if results the same as with the provider
openssl aes-256-cbc -provider default -pass pass:1111 -d -nosalt -pbkdf2 -in data.txt.cipher.pbkdf2.encrypt -out data.txt.cipher.pbkdf2.no_pkcs11.decrypt
cmp data.txt.cipher.pbkdf2.decrypt data.txt.cipher.pbkdf2.no_pkcs11.decrypt
print_result $?

## Key generation not supported yet. Generate key pair on the token with another tool first, than you can use in libp11.
#echo "=================================="
#echo "RSA generate key pair"
#openssl genrsa -provider pkcs11prov -out "pkcs11://"$PKCS11URI_RSA_NEWPAIR 2048
#print_result $?

echo "=================================="
echo "RSA create csr"
## Not working with opencryptoki openssl 3 backed software token (digest context is not copyable in this case)
#openssl req -provider pkcs11prov -new -subj "/C=HU/O=ACME/CN=test_cert" -sha256 -key "pkcs11://"$PKCS11URI_RSA -out ./pkcs11_test.csr
#
## This one turns of digest in libp11 and allows openssl to use the default provider for that purpose
OPENSSL_CONF=$OPENSSL_CONF_NO_DIGEST openssl req -provider pkcs11prov -provider default -new -subj "/C=HU/O=ACME/CN=test_cert" -sha256 -key "pkcs11://"$PKCS11URI_RSA -out ./pkcs11_test.csr
print_result $?

echo "=================================="
echo "RSA sign"
openssl pkeyutl -provider pkcs11prov -sign -inkey "pkcs11://"$PKCS11URI_RSA -in ./data.txt >./data.txt.rsa.signature
print_result $?

echo "=================================="
echo "RSA verify"
openssl pkeyutl -provider pkcs11prov -verify -inkey "pkcs11://"$PKCS11URI_RSA -in ./data.txt -sigfile ./data.txt.rsa.signature
print_result $?

echo "=================================="
echo "RSA encrypt"
openssl pkeyutl -provider pkcs11prov -encrypt -inkey "pkcs11://"$PKCS11URI_RSA -in ./data.txt >./data.txt.rsa.encrypt
print_result $?

echo "=================================="
echo "RSA decrypt"
openssl pkeyutl -provider pkcs11prov -decrypt -inkey "pkcs11://"$PKCS11URI_RSA -in ./data.txt.rsa.encrypt >./data.txt.rsa.decrypt
print_result $?

echo "=================================="
echo "EC create csr"
## Not working with opencryptoki openssl 3 backed software token (digest context is not copyable in this case)
#openssl req -provider pkcs11prov -new -subj "/C=HU/O=ACME/CN=test_cert_eckey" -sha256 -key "pkcs11://"$PKCS11URI_EC -out ./pkcs11_test_eckey.csr
#
## This one turns of digest in libp11 and allows openssl to use the default provider for that purpose
OPENSSL_CONF=$OPENSSL_CONF_NO_DIGEST openssl req -provider pkcs11prov -provider default -new -subj "/C=HU/O=ACME/CN=test_cert_eckey" -sha256 -key "pkcs11://"$PKCS11URI_EC -out ./pkcs11_test_eckey.csr
print_result $?

echo "=================================="
echo "EC sign"
openssl pkeyutl -provider pkcs11prov -sign -inkey "pkcs11://"$PKCS11URI_EC -in ./data.txt >./data.txt.ec.signature
print_result $?

echo "=================================="
echo "EC verify"
openssl pkeyutl -provider pkcs11prov -verify -inkey "pkcs11://"$PKCS11URI_EC -in ./data.txt -sigfile ./data.txt.ec.signature
print_result $?

echo "=================================="
echo "Random number"
openssl rand -provider pkcs11prov -hex 20
print_result $?
