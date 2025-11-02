EXTRA_DIST = engines.cnf.in common.sh openssl-settings.sh helpers_prov.h eddsa_common.h

AM_CFLAGS = $(OPENSSL_CFLAGS)
AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/src \
	-I$(top_builddir)

AM_LDFLAGS = -no-install
LDADD = ../src/libp11.la $(OPENSSL_LIBS)

check_PROGRAMS = \
	openssl_version \
	evp-sign \
	evp-sign-prov \
	fork-test \
	fork-change-slot \
	fork-change-slot-prov \
	list-tokens \
	rsa-pss-sign \
	rsa-pss-sign-prov \
	rsa-oaep \
	rsa-oaep-prov \
	check-privkey \
	check-privkey-prov \
	dup-key \
	dup-key-prov \
	check-all-prov \
	rsa-keygen \
	ec-keygen \
	ed25519-keygen \
	ed448-keygen \
	ed25519-keygen-prov \
	ed448-keygen-prov
dist_check_SCRIPTS = \
	rsa-testpkcs11.softhsm \
	rsa-testfork.softhsm \
	rsa-testlistkeys.softhsm \
	rsa-testlistkeys_ext.softhsm \
	rsa-evp-sign.softhsm \
	rsa-pss-sign.softhsm \
	rsa-oaep.softhsm \
	rsa-check-privkey.softhsm \
	rsa-cert-store.softhsm \
	rsa-keygen.softhsm \
	ec-testfork.softhsm \
	ec-evp-sign.softhsm \
	ec-check-privkey.softhsm \
	ec-cert-store.softhsm \
	ec-copy.softhsm \
	ec-keygen.softhsm \
	ed25519-keygen.softhsm \
	ed448-keygen.softhsm \
	fork-change-slot.softhsm \
	case-insensitive.softhsm \
	pkcs11-uri-pin-source.softhsm \
	pkcs11-uri-without-token.softhsm \
	search-all-matching-tokens.softhsm \
	provider-rsa-evp-sign.softhsm \
	provider-rsa-pss-sign.softhsm \
	provider-rsa-oaep.softhsm \
	provider-rsa-check-privkey.softhsm \
	provider-rsa-check-all.softhsm \
	provider-ec-evp-sign.softhsm \
	provider-ec-check-privkey.softhsm \
	provider-ec-check-all.softhsm \
	provider-ec-copy.softhsm \
	provider-ed25519-keygen.softhsm \
	provider-ed448-keygen.softhsm \
	provider-fork-change-slot.softhsm \
	provider-case-insensitive.softhsm \
	provider-pkcs11-uri-without-token.softhsm \
	provider-search-all-matching-tokens.softhsm
dist_check_DATA = \
	rsa-cert.der rsa-privkey.der rsa-pubkey.der \
	ec-cert.der ec-privkey.der ec-pubkey.der

ed25519_keygen_SOURCES = ed25519-keygen.c eddsa_common.c
ed448_keygen_SOURCES = ed448-keygen.c eddsa_common.c
ed25519_keygen_prov_SOURCES = ed25519-keygen-prov.c helpers_prov.c eddsa_common.c
ed448_keygen_prov_SOURCES = ed448-keygen-prov.c helpers_prov.c eddsa_common.c
evp_sign_prov_SOURCES = evp-sign-prov.c helpers_prov.c
fork_change_slot_prov_SOURCES = fork-change-slot-prov.c helpers_prov.c
dup_key_prov_SOURCES = dup-key-prov.c helpers_prov.c
check_privkey_prov_SOURCES = check-privkey-prov.c helpers_prov.c
rsa_pss_sign_prov_SOURCES = rsa-pss-sign-prov.c helpers_prov.c
rsa_oaep_prov_SOURCES = rsa-oaep-prov.c helpers_prov.c
check_all_prov_SOURCES = check-all-prov.c helpers_prov.c

TESTS = $(dist_check_SCRIPTS)

TESTS_ENVIRONMENT =	\
	LC_ALL="C" \
	EXEEXT=$(EXEEXT) \
	PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" \
	top_builddir="$(top_builddir)" \
	srcdir="$(srcdir)"

# vim: set noexpandtab:
