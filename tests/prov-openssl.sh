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
    OSSL_MODULES_DIRS="/usr/local/lib/ossl-modules /usr/lib/x86_64-linux-gnu/ossl-modules"
    unset LIB_PROVIDER_LEGACY
    for CHECK_DIR in $OSSL_MODULES_DIRS
    do
        if [ -f "$CHECK_DIR/legacy.so" ]; then
            LIB_PROVIDER_LEGACY="$CHECK_DIR/legacy.so"
            break
        fi
    done

    echo "Opencryptoki uses OpenSSL and needs the legacy provider. Some other tools may work similarly."
    echo "In case you face issues because of the missing legacy provider, please make sure that the"
    echo "legacy provider's shared library also available in $OPENSSL_MODULES"
    echo
    echo "To dismiss this warning, export NO_LEGACY_CHECK=1"
    echo
    if [ ! -z $LIB_PROVIDER_LEGACY ]; then
    echo "You may try:"
    echo  "  ln -s $LIB_PROVIDER_LEGACY $OPENSSL_MODULES"
    echo
    fi
fi

echo "Please create an RSA and an EC key pair on your smartcard/HSM, also import a certificate"
echo "Then update the key pair URIs in this script"
echo
echo "In case of opencryptoki, one may use something like:"
echo "  pkcs11-tool --module \$LIBOPENCRYPTOKI -l --login-type user -a my_rsa_keypair -k --key-type rsa:2048 --usage-sign -y cert -d 01"
echo "  pkcs11-tool --module \$LIBOPENCRYPTOKI -l --login-type user -a my_ec_keypair -k --key-type ec:prime256v1 --usage-sign -y cert -d 11"
echo
echo "Make sure that no key exists with the uri of the new keypair"
echo 
echo "In case of opencryptoki, one may use something like this to remove public and private keys:"
echo "  pkcs11-tool --module $LIBOPENCRYPTOKI -l --login-type user -b -y pubkey -d 21"
echo "  pkcs11-tool --module $LIBOPENCRYPTOKI -l --login-type user -b -y privkey -d 21"
echo

PKCS11URI_RSA="pkcs11:id=%01"
PKCS11URI_EC="pkcs11:id=%11"
PKCS11URI_RSA_NEWPAIR="pkcs11:object=my_rsa;id=%21"
#PKCS11URI_EC_NEWPAIR="pkcs11:object=my_ec;id=%31"
PKCS11URI_CERT="pkcs11:id=%02"

print_variable PKCS11URI_RSA
print_variable PKCS11URI_EC
print_variable PKCS11URI_RSA_NEWPAIR
#print_variable PKCS11URI_EC_NEWPAIR
print_variable PKCS11URI_CERT
echo

# create output folder
OUTDIR="output."$$
rm -rf $OUTDIR
mkdir $OUTDIR

# prepare some data
echo "something to sign" >$OUTDIR/data.txt
echo "and it has a second line too" >>$OUTDIR/data.txt

#
# tests
#

echo "=================================="
echo "check if provider loaded correctly"
openssl list -provider pkcs11prov -providers >$OUTDIR/providers.txt
RES=$?
print_result $RES
if [ $RES -ne 0 ]; then
    exit $RES
fi

echo "=================================="
echo "make a hash"
openssl dgst -provider pkcs11prov -sha256 $OUTDIR/data.txt >$OUTDIR/hash.txt
print_result $?

## No KDF supported yet
#echo "=================================="
#echo "make key derivation"
#openssl kdf -provider pkcs11prov -keylen 32 -kdfopt digest:SHA256 -kdfopt pass:password -kdfopt salt:salt -kdfopt iter:2 PBKDF2
#print_result $?

echo "=================================="
echo "cipher encrypt"
openssl aes-256-cbc -provider pkcs11prov -pass pass:1111 -salt -in $OUTDIR/data.txt -out $OUTDIR/data.txt.cipher.encrypt
print_result $?

echo "=================================="
echo "cipher decrypt"
openssl aes-256-cbc -provider pkcs11prov -pass pass:1111 -d -salt -in $OUTDIR/data.txt.cipher.encrypt -out $OUTDIR/data.txt.cipher.decrypt

# OK if we can decrypt without pkcs11 AND the resulting file is the same
openssl aes-256-cbc -provider default -pass pass:1111 -d -salt -in $OUTDIR/data.txt.cipher.encrypt -out $OUTDIR/data.txt.cipher.no_pkcs11.decrypt
cmp $OUTDIR/data.txt.cipher.decrypt $OUTDIR/data.txt.cipher.no_pkcs11.decrypt
print_result $?

echo "=================================="
echo "cipher with PBKDF2 test"
# Note 1: KDF not yet supported, hence "-provider default" required to provide the PBKDF2 algorithm
# Note 2: OpenSSL implementation of PBKDF2 requires digest session state saving (it duplicates session after some date sent into),
#         but Opencryptoki SW implementation does not support session state saving with OpenSSL3, hence digest disabled in these
#         samples, with using another OpenSSL config 
#
OPENSSL_CONF=$OPENSSL_CONF_NO_DIGEST openssl aes-256-cbc -provider pkcs11prov -provider default -pass pass:1111 -nosalt -pbkdf2 -in $OUTDIR/data.txt -out $OUTDIR/data.txt.cipher.pbkdf2.encrypt
OPENSSL_CONF=$OPENSSL_CONF_NO_DIGEST openssl aes-256-cbc -provider pkcs11prov -provider default -pass pass:1111 -d -nosalt -pbkdf2 -in $OUTDIR/data.txt.cipher.pbkdf2.encrypt -out $OUTDIR/data.txt.cipher.pbkdf2.decrypt
# Try to decrypt without provider and check if results the same as with the provider
openssl aes-256-cbc -provider default -pass pass:1111 -d -nosalt -pbkdf2 -in $OUTDIR/data.txt.cipher.pbkdf2.encrypt -out $OUTDIR/data.txt.cipher.pbkdf2.no_pkcs11.decrypt
cmp $OUTDIR/data.txt.cipher.pbkdf2.decrypt $OUTDIR/data.txt.cipher.pbkdf2.no_pkcs11.decrypt
print_result $?

echo "=================================="
echo "Print certificate"
openssl x509 -provider pkcs11prov -in "pkcs11://"$PKCS11URI_CERT
print_result $?

#echo "=================================="
#echo "RSA generate key pair"
## openssl apps/genpkey.c wants to write the resulting keypair into a file, but 
## extracting private key details from the token is not supported, hence the
## openssl fails (although only after the keypair is created as expected)
## 
## with the following patch on apps/genpkey.c one could try to avoid the error:
##
## 227,229c227,231
## <     out = bio_open_owner(outfile, outformat, private);
## <     if (out == NULL)
## <         goto end;
## ---
## >     if (outfile) {
## >         out = bio_open_owner(outfile, outformat, private);
## >         if (out == NULL)
## >             goto end;
## >     }
## 238,249c240,252
## <     if (do_param) {
## <         rv = PEM_write_bio_Parameters(out, pkey);
## <     } else if (outformat == FORMAT_PEM) {
## <         assert(private);
## <         rv = PEM_write_bio_PrivateKey(out, pkey, cipher, NULL, 0, NULL, pass);
## <     } else if (outformat == FORMAT_ASN1) {
## <         assert(private);
## <         rv = i2d_PrivateKey_bio(out, pkey);
## <     } else {
## <         BIO_printf(bio_err, "Bad format specified for key\n");
## <         goto end;
## <     }
## ---
## >     if (outfile) {
## >         if (do_param) {
## >             rv = PEM_write_bio_Parameters(out, pkey);
## >         } else if (outformat == FORMAT_PEM) {
## >             assert(private);
## >             rv = PEM_write_bio_PrivateKey(out, pkey, cipher, NULL, 0, NULL, pass);
## >         } else if (outformat == FORMAT_ASN1) {
## >             assert(private);
## >             rv = i2d_PrivateKey_bio(out, pkey);
## >         } else {
## >             BIO_printf(bio_err, "Bad format specified for key\n");
## >             goto end;
## >         }
## 251c254
## <     ret = 0;
## ---
## >         ret = 0;
### 253,255c256,263
## <     if (rv <= 0) {
## <         BIO_puts(bio_err, "Error writing key\n");
## <         ret = 1;
## ---
## >         if (rv <= 0) {
## >             BIO_puts(bio_err, "Error writing key\n");
## >             ret = 1;
## >         }
## >     }
## >     else {
## >         BIO_puts(bio_out, "Not writing key to file\n");
## >         ret = 0;
##
## TODO: would be better to use "-pass" to get the token PIN and "-out" to get the target uri
##
## TODO: the "openssl genrsa" could be patched, since there are more examples for that
##
#openssl genpkey -provider pkcs11prov -algorithm RSA -pkeyopt pass:1111 -pkeyopt uri:$PKCS11URI_RSA_NEWPAIR -pkeyopt bits:2048
#print_result $?

echo "=================================="
echo "RSA print public key"
openssl rsa -provider pkcs11prov -in "pkcs11://"$PKCS11URI_RSA -pubout
print_result $?

echo "=================================="
echo "RSA create csr"
## Not working with opencryptoki openssl 3 backed software token (digest context is not copyable in this case)
#openssl req -provider pkcs11prov -new -subj "/C=HU/O=ACME/CN=test_cert" -sha256 -key "pkcs11://"$PKCS11URI_RSA -out $OUTDIR/pkcs11_test.csr
#
## This one turns of digest in libp11 and allows openssl to use the default provider for that purpose
OPENSSL_CONF=$OPENSSL_CONF_NO_DIGEST openssl req -provider pkcs11prov -provider default -new -subj "/C=HU/O=ACME/CN=test_cert" -sha256 -key "pkcs11://"$PKCS11URI_RSA -out $OUTDIR/pkcs11_test.csr
print_result $?

echo "=================================="
echo "RSA sign"
openssl pkeyutl -provider pkcs11prov -sign -inkey "pkcs11://"$PKCS11URI_RSA -in $OUTDIR/data.txt >$OUTDIR/data.txt.rsa.signature
print_result $?

echo "=================================="
echo "RSA verify"
openssl pkeyutl -provider pkcs11prov -verify -inkey "pkcs11://"$PKCS11URI_RSA -in $OUTDIR/data.txt -sigfile $OUTDIR/data.txt.rsa.signature
print_result $?

echo "=================================="
echo "RSA encrypt"
openssl pkeyutl -provider pkcs11prov -encrypt -inkey "pkcs11://"$PKCS11URI_RSA -in $OUTDIR/data.txt >$OUTDIR/data.txt.rsa.encrypt
print_result $?

echo "=================================="
echo "RSA decrypt"
openssl pkeyutl -provider pkcs11prov -decrypt -inkey "pkcs11://"$PKCS11URI_RSA -in $OUTDIR/data.txt.rsa.encrypt >$OUTDIR/data.txt.rsa.decrypt
print_result $?

#echo "=================================="
#echo "EC generate key pair"
## same comment applies as in case of RSA keypair generation
##
## "genpkey" has more generic parameter definition as "ecparam", here's how it looks:
##   group: this is the curve name
##   encoding: named_curve OR explicit
##   point-format: uncompressed OR compressed OR hybrid
##
## note that there's no check on the "encoding" and "point-format"... if wrongly supplied, openssl would assign some default
##
## TODO: the "openssl ecparam" could be patched, since there are more examples for that
##
#openssl genpkey -provider pkcs11prov -algorithm EC -pkeyopt pass:1111 -pkeyopt uri:$PKCS11URI_RSA_NEWPAIR -pkeyopt group:secp256r1 -pkeyopt encoding:named_curve -pkeyopt point-format:uncompressed
#print_result $?

#echo "=================================="
#echo "EC print public key"
## openssl apps/ec.c does not tries to use the legacy encoder if OSSL_ENCODER_CTX_new_for_pkey() loads no encoders (in opposite to rsa.c);
## also there's an issue around setting OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC 
## 
## with the following patch on apps/ec.c one could try:
## 
## 63a64,83
## > static int try_legacy_encoding(EVP_PKEY *eckey, int outformat, int pubout,
## >                                BIO *out)
## > {
## >     int ret = 0;
## > #ifndef OPENSSL_NO_DEPRECATED_3_0
## >     const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(eckey);
## > 
## >     if (ec == NULL)
## >         return 0;
## > 
## >     if (outformat == FORMAT_ASN1) {
## >         ret = i2d_EC_PUBKEY_bio(out, ec) > 0;
## >     } else if (outformat == FORMAT_PEM) {
## >         ret = PEM_write_bio_EC_PUBKEY(out, ec) > 0;
## >     }
## > #endif
## > 
## >     return ret;
## > }
## > 
## 203c223
## < 
## ---
## > /*
## 215c235
## < 
## ---
## > */
## 257a278,287
## > 
## >         if (OSSL_ENCODER_CTX_get_num_encoders(ectx) == 0) {
## >             if ((!pubout && !pubin)
## >                 || !try_legacy_encoding(eckey, outformat, pubout, out))
## >                 BIO_printf(bio_err, "%s format not supported\n", output_type);
## >             else
## >                 ret = 0;
## >             goto end;
## >         }
## > 
## 
#openssl ec -provider pkcs11prov -in "pkcs11://"$PKCS11URI_EC -pubout
#print_result $?

echo "=================================="
echo "EC create csr"
## Not working with opencryptoki openssl 3 backed software token (digest context is not copyable in this case)
#openssl req -provider pkcs11prov -new -subj "/C=HU/O=ACME/CN=test_cert_eckey" -sha256 -key "pkcs11://"$PKCS11URI_EC -out $OUTDIR/pkcs11_test_eckey.csr
#
## This one turns of digest in libp11 and allows openssl to use the default provider for that purpose
OPENSSL_CONF=$OPENSSL_CONF_NO_DIGEST openssl req -provider pkcs11prov -provider default -new -subj "/C=HU/O=ACME/CN=test_cert_eckey" -sha256 -key "pkcs11://"$PKCS11URI_EC -out $OUTDIR/pkcs11_test_eckey.csr
print_result $?

echo "=================================="
echo "EC sign"
openssl pkeyutl -provider pkcs11prov -sign -inkey "pkcs11://"$PKCS11URI_EC -in $OUTDIR/data.txt >$OUTDIR/data.txt.ec.signature
print_result $?

echo "=================================="
echo "EC verify"
openssl pkeyutl -provider pkcs11prov -verify -inkey "pkcs11://"$PKCS11URI_EC -in $OUTDIR/data.txt -sigfile $OUTDIR/data.txt.ec.signature
print_result $?

echo "=================================="
echo "Random number"
openssl rand -provider pkcs11prov -hex 20 >$OUTDIR/rand.txt
print_result $?


#
# LD_PRELOAD="/home/zoli/git/openssl/libcrypto.so.3 /home/zoli/git/openssl/libssl.so.3" gdb --args $OPENSSL ecparam -genkey -name prime256v1 -noout -provider pkcs11prov -out "pkcs11://"$PKCS11URI_EC_NEWPAIR
# LD_PRELOAD="/home/zoli/git/openssl/libcrypto.so.3 /home/zoli/git/openssl/libssl.so.3" gdb --args $OPENSSL genrsa -verbose -provider pkcs11prov -out "pkcs11://"$PKCS11URI_RSA_NEWPAIR 2048
#
# LD_PRELOAD="/home/zoli/git/openssl/libcrypto.so.3 /home/zoli/git/openssl/libssl.so.3" gdb --args $OPENSSL genpkey -provider pkcs11prov -out "pkcs11://"$PKCS11URI_RSA_NEWPAIR -algorithm RSA -pkeyopt bits:2048
#
