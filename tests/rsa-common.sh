#!/bin/sh

# Copyright (C) 2013 Nikos Mavrogiannopoulos
# Copyright (C) 2015 Red Hat, Inc.
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at
# your option) any later version.
#
# GnuTLS is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GnuTLS; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

echo "Current directory: $(pwd)"
echo "Source directory: ${srcdir}"
echo "Output directory: ${outdir}"

mkdir -p $outdir

# Set the module to be used
for i in /usr/lib64/pkcs11 /usr/lib64/softhsm /usr/lib/x86_64-linux-gnu/softhsm \
	/usr/local/lib/softhsm /opt/local/lib/softhsm /usr/lib/softhsm /usr/lib ;do
	if test -f "$i/libsofthsm2.so"; then
		MODULE="$i/libsofthsm2.so"
		break
	else
		if test -f "$i/libsofthsm.so";then
			MODULE="$i/libsofthsm.so"
			break
		fi
	fi
done

if (! test -x /usr/bin/pkcs11-tool && ! test -x /usr/local/bin/pkcs11-tool);then
	exit 77
fi

# Initialize the SoftHSM DB
init_db () {
	if test -x "/usr/bin/softhsm"; then
		export SOFTHSM_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/usr/bin/softhsm"
		SLOT="--slot 0"
	fi

	if test -x "/usr/local/bin/softhsm2-util"; then
		export SOFTHSM2_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/usr/local/bin/softhsm2-util"
		SLOT="--free "
	fi

	if test -x "/opt/local/bin/softhsm2-util"; then
		export SOFTHSM2_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/opt/local/bin/softhsm2-util"
		SLOT="--free "
	fi

	if test -x "/usr/bin/softhsm2-util"; then
		export SOFTHSM2_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/usr/bin/softhsm2-util"
		SLOT="--free "
	fi

	if test -z "${SOFTHSM_TOOL}"; then
		echo "Could not find softhsm(2) tool"
		exit 77
	fi

	if test -n "${SOFTHSM2_CONF}"; then
		rm -rf $outdir/softhsm-testpkcs11.db
		mkdir -p $outdir/softhsm-testpkcs11.db
		echo "objectstore.backend = file" > "${SOFTHSM2_CONF}"
		echo "directories.tokendir = $outdir/softhsm-testpkcs11.db" >> \
			"${SOFTHSM2_CONF}"
	else
		rm -rf $outdir/softhsm-testpkcs11.db
		echo "0:$outdir/softhsm-testpkcs11.db" > "${SOFTHSM_CONF}"
	fi
}

# Create a new device
init_card () {
	PIN="$1"
	PUK="$2"
	DEV_LABEL="$3"

	echo -n "* Initializing smart card... "
	${SOFTHSM_TOOL} --init-token ${SLOT} --label "${DEV_LABEL}" \
		--so-pin "${PUK}" --pin "${PIN}" >/dev/null
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit 1
	fi
}

# Import objects to the token
import_objects () {
	ID=$1
	OBJ_LABEL=$2

	pkcs11-tool -p ${PIN} --module ${MODULE} -d ${ID} -a ${OBJ_LABEL} -l -w \
		${srcdir}/rsa-prvkey.der -y privkey >/dev/null
	if test $? != 0;then
		exit 1;
	fi

	pkcs11-tool -p ${PIN} --module ${MODULE} -d ${ID} -a ${OBJ_LABEL} -l -w \
		${srcdir}/rsa-pubkey.der -y pubkey >/dev/null
	if test $? != 0;then
		exit 1;
	fi

	pkcs11-tool -p ${PIN} --module ${MODULE} -d ${ID} -a ${OBJ_LABEL} -l -w \
		${srcdir}/rsa-cert.der -y cert >/dev/null
	if test $? != 0;then
		exit 1;
	fi

	echo Finished
}

# List the objects contained in the token
list_objects () {
	echo "***************"
	echo "Listing objects"
	echo "***************"
	pkcs11-tool -p ${PIN} --module ${MODULE} -l -O
}

common_init () {
	# Set the used PIN and PUK
	PIN=1234
	PUK=1234

	# Initialize the SoftHSM DB
	init_db

	# Initialize a new device
	init_card $PIN $PUK "libp11-test"

	echo Importing
	# Import the used objects (private key, public key, and certificate)
	import_objects 01020304 "server-key"

	# List the imported objects
	list_objects
}
