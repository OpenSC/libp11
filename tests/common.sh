#!/bin/bash

# Copyright © 2024 Mobi - Com Polska Sp. z o.o.
# Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
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

# Uncomment the following line to enable debugging with Valgrind
# WRAPPER="valgrind -s --track-origins=yes --leak-check=full --show-leak-kinds=all --tool=memcheck --show-reachable=yes --keep-debuginfo=yes"

echo "Current directory: $(pwd)"
echo "Source directory: ${srcdir}"
echo "Output directory: ${outdir}"

mkdir -p ${outdir}

for i in /usr/local/lib/softhsm /opt/local/lib/softhsm /usr/lib64/pkcs11 \
		/usr/lib64/softhsm /usr/lib/x86_64-linux-gnu/softhsm /usr/lib/softhsm /usr/lib; do
	if [[ -f "$i/libsofthsm2.so" ]]; then
		MODULE="$i/libsofthsm2.so"
		break
	else
		if [[ -f "$i/libsofthsm.so" ]]; then
			MODULE="$i/libsofthsm.so"
			break
		fi
	fi
done

if [[ ! -x /usr/bin/pkcs11-tool && ! -x /usr/local/bin/pkcs11-tool ]]; then
	echo "Skipping test: 'pkcs11-tool' not found. Please install the tool to proceed."
	exit 77
fi

# Load openssl settings
TEMP_LD_LIBRARY_PATH=${LD_LIBRARY_PATH}
. ${srcdir}/openssl-settings.sh

OPENSSL_VERSION=$(./openssl_version | cut -d ' ' -f 2)

# Restore settings
export LD_LIBRARY_PATH=${TEMP_LD_LIBRARY_PATH}

# Check for ldd command
if command -v ldd >/dev/null 2>&1; then
	LIBCRYPTO_VER=$(ldd "${MODULE}" | grep 'libcrypto' | awk '{print $1}')
else
	echo "Warning: ldd command not found. Skipping library version detection."
	LIBCRYPTO_VER="unknown"
fi

# Check OpenSSL version and library compatibility
if [[ "$OPENSSL_VERSION" =~ ^0.* || "$OPENSSL_VERSION" =~ ^1\.0.* ]]; then
	if [[ "$LIBCRYPTO_VER" == "libcrypto.so.3" ]]; then
		echo -n "Skipping test: Module '${MODULE}' built with '${LIBCRYPTO_VER}'"
		echo "is incompatible with OpenSSL version '${OPENSSL_VERSION}'."
		exit 77
	fi
fi

echo "Detected system: ${OSTYPE}"

if [[ ${OSTYPE} == darwin* ]]; then
	SHARED_EXT=.dylib
else
	SHARED_EXT=.so
fi


sed -e "s|@MODULE_PATH@|${MODULE}|g" -e \
	"s|@ENGINE_PATH@|../src/.libs/pkcs11${SHARED_EXT}|g" \
	<"${srcdir}/engines.cnf.in" >"${outdir}/engines.cnf"

# Force the use of the local built engine
export OPENSSL_ENGINES="../src/.libs/"
echo "OPENSSL_ENGINES=${OPENSSL_ENGINES}"

# Set the used PIN and PUK
PIN=1234
PUK=1234

# Set the default object ID for operations
ID=01020304

# Initialize the SoftHSM DB
init_db () {
	if [[ -x "/usr/bin/softhsm" ]]; then
		export SOFTHSM_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/usr/bin/softhsm"
		SLOT="--slot 0"
	fi

	if [[ -x "/usr/local/bin/softhsm2-util" ]]; then
		export SOFTHSM2_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/usr/local/bin/softhsm2-util"
		SLOT="--free "
	fi

	if [[ -x "/opt/local/bin/softhsm2-util" ]]; then
		export SOFTHSM2_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/opt/local/bin/softhsm2-util"
		SLOT="--free "
	fi

	if [[ -x "/usr/bin/softhsm2-util" ]]; then
		export SOFTHSM2_CONF="$outdir/softhsm-testpkcs11.config"
		SOFTHSM_TOOL="/usr/bin/softhsm2-util"
		SLOT="--free "
	fi

	if [[ -z ${SOFTHSM_TOOL} ]]; then
		echo "Could not find softhsm(2) tool"
		exit 77
	fi

	if [[ -n ${SOFTHSM2_CONF} ]]; then
		rm -rf $outdir/softhsm-testpkcs11.db
		mkdir -p $outdir/softhsm-testpkcs11.db
		echo "objectstore.backend = file" > "${SOFTHSM2_CONF}"
		echo "directories.tokendir = $outdir/softhsm-testpkcs11.db" >> \
			${SOFTHSM2_CONF}
	else
		rm -rf $outdir/softhsm-testpkcs11.db
		echo "0:$outdir/softhsm-testpkcs11.db" > ${SOFTHSM_CONF}
	fi
	echo "SOFTHSM2_CONF=${SOFTHSM2_CONF}"
}

# Initialize a token in the first available slot
init_card () {
	local token_label="$1"

	echo "***************************************"
	echo -n "* Initializing token ${token_label} ... "
	${SOFTHSM_TOOL} --init-token ${SLOT} --label ${token_label} \
		--so-pin ${PUK} --pin ${PIN} >/dev/null
	if [[ $? -eq 0 ]]; then
		echo ok
	else
		echo failed
		exit 1
	fi
}

# Delete the token at a given slot
remove_card () {
	local token_label="$1"

	echo "* Removing token ${token_label}"
	${SOFTHSM_TOOL} --delete-token --token ${token_label}
	if [[ $? -ne 0 ]]; then
		exit 1
	fi
}

# Generate an RSA key pair on the token
generate_rsa_key_pair () {
	local obj_label="$1"
	local token_label="$2"

	echo "* Generating an RSA key pair on the token ${token_label}"
	pkcs11-tool --login --pin ${PIN} --module ${MODULE} --id ${ID} \
		--keypairgen --key-type "rsa:2048" \
		--label ${obj_label} --token-label ${token_label}
	if [[ $? -ne 0 ]]; then
		exit 1
	fi
}

# Do the token initialization
init_token () {
	local key_type="$1"
	local num_devices="$2"
	local common_label="$3"
	local obj_id="$4"
	local obj_label="$5"
	local i=0

	# Remove the first 5 parameters from the list of arguments
	shift 5

	# Initialize SoftHSM DB
	init_db

	while [[ $i -lt ${num_devices} ]]; do
		# Initialize a new device
		init_card "${common_label}-$i"

		# Import objects with different labels
		import_objects ${key_type} "${common_label}-$i" ${obj_id} "${obj_label}-$i" "$@"

		# List the objects imported into the token
		list_objects "${common_label}-$i"

		i=$(($i + 1))
	done
}

# Write an object (privkey, pubkey, cert) to the token
import_objects () {
	local key_type="$1"
	local token_label="$2"
	local obj_id="$3"
	local obj_label="$4"

	# Remove the first 4 parameters from the list of arguments
	shift 4

	# Import objects with different labels
	for param in "$@"; do
		if [[ -n "$param" ]]; then
			echo -n "* Importing the ${key_type} ${param} object id=${obj_id}"
			echo -n " into the token ${token_label} ... "
			pkcs11-tool --login --pin ${PIN} --module ${MODULE} \
				--token-label "${token_label}"\
				--write-object "${srcdir}/${key_type}-${param}.der" \
				--type ${param} \
				--id ${obj_id} --label "${obj_label}" >/dev/null
			if [[ $? -eq 0 ]]; then
				echo ok
			else
				echo failed
				exit 1
			fi
		else
			echo "Skipping empty parameter"
		fi
	done
}

# Show objects on the token
list_objects () {
	local token_label="$1"

	echo "***************************************"
	echo "* Listing objects on the token ${token_label}"
	echo "***************************************"
	pkcs11-tool --login --pin ${PIN} --module ${MODULE} \
		--token-label "${token_label}" --list-objects
	if [[ $? -ne 0 ]]; then
		exit 1
	fi
	echo "***************************************"
}
