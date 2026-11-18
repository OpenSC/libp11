#!/bin/bash

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# Parse PKCS#11 URIs (RFC 7512) without a token and check the result

# Load OpenSSL settings
. "${srcdir}/openssl-settings.sh"

failed=0

# expect_ok <uri> <expected output> [<object type>]
expect_ok()
{
	local out
	out=$(${WRAPPER} ./parse-uri${EXEEXT} "$1" ${3:+"$3"} 2>&1)
	if [[ $? -ne 0 || "${out}" != "$2" ]]; then
		echo "FAIL: $1"
		echo "  expected: $2"
		echo "  got:      ${out}"
		failed=1
	fi
}

# expect_fail <uri> [<object type>]
expect_fail()
{
	if ${WRAPPER} ./parse-uri${EXEEXT} "$1" ${2:+"$2"} >/dev/null 2>&1; then
		echo "FAIL (accepted): $1"
		failed=1
	fi
}

expect_ok "pkcs11:token=A%20b;object=c" "token=412062
object=63"
expect_ok "PKCS11:token=A" "token=41"
expect_ok "pkcs11:slot-description=S;slot-manufacturer=M;slot-id=7" \
	"slot-description=53
slot-manufacturer=4D
slot-id=7"
expect_ok "pkcs11:library-description=D;library-manufacturer=M;library-version=2" \
	"library-description=44
library-manufacturer=4D
library-version=2.0"
expect_ok "pkcs11:library-version=2.17" "library-version=2.17"
expect_ok "pkcs11:id=%01%02?pin-value=1234" "id=0102
pin-value=1234"
expect_ok "pkcs11:id=" "id="
expect_ok "pkcs11:module-name=softhsm2?module-path=/usr/lib/libsofthsm2.so" \
	"module-name=softhsm2
module-path=/usr/lib/libsofthsm2.so"
expect_ok "pkcs11:object=k;type=private" "object=6B
type=private" "private key"
expect_ok "pkcs11:object=k;object-type=cert" "object=6B
type=cert" "certificate"

# an ID is not limited by the PIN buffer size
id=""
hex=""
for i in $(seq 1 300); do
	id="${id}%ab"
	hex="${hex}AB"
done
expect_ok "pkcs11:id=${id}" "id=${hex}"

# a PIN is a C string, so an encoded NUL must be rejected
expect_fail "pkcs11:pin-value=a%00b"
expect_fail "pkcs11:object=x?pin-value=a%00$(printf '%0200d' 0)"

expect_fail "pkcs11:library-version=2.6garbage"
expect_fail "pkcs11:library-version=2."
expect_fail "pkcs11:library-version=.6"
expect_fail "pkcs11:library-version=256"
expect_fail "pkcs11:slot-id=x"
expect_fail "pkcs11:slot-id=-1"
expect_fail "pkcs11:type=secret-key"
expect_fail "pkcs11:object=k;type=public" "private key"

# duplicate attributes
expect_fail "pkcs11:token=A;token=B"
expect_fail "pkcs11:id=%01;id=%02"
expect_fail "pkcs11:slot-id=1;slot-id=1"
expect_fail "pkcs11:library-version=1;library-version=1"
expect_fail "pkcs11:type=cert;object-type=cert"
expect_fail "pkcs11:object=k?pin-value=1&pin-value=1"

exit ${failed}
