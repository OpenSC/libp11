EXTRA_DIST = engines.cnf.in rsa-common.sh rsa-no-pubkey.sh ec-common.sh ec-no-pubkey.sh

AM_CFLAGS = $(OPENSSL_CFLAGS)
AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/src \
	-I$(top_builddir)

AM_LDFLAGS = -no-install
LDADD = ../src/libp11.la $(OPENSSL_LIBS)

check_PROGRAMS = \
	openssl_version \
	fork-test evp-sign \
	fork-change-slot \
	list-tokens \
	rsa-pss-sign \
	rsa-oaep \
	check-privkey \
	store-cert \
	dup-key
dist_check_SCRIPTS = \
	rsa-testpkcs11.softhsm \
	rsa-testfork.softhsm \
	rsa-testlistkeys.softhsm \
	rsa-testlistkeys_ext.softhsm \
	rsa-evp-sign.softhsm \
	ec-evp-sign.softhsm \
	ec-testfork.softhsm \
	fork-change-slot.softhsm \
	rsa-pss-sign.softhsm \
	rsa-oaep.softhsm \
	case-insensitive.softhsm \
	rsa-check-privkey.softhsm \
	ec-check-privkey.softhsm \
	pkcs11-uri-without-token.softhsm \
	search-all-matching-tokens.softhsm \
	ec-cert-store.softhsm \
	ec-copy.softhsm
dist_check_DATA = \
	rsa-cert.der rsa-prvkey.der rsa-pubkey.der \
	ec-cert.der ec-prvkey.der ec-pubkey.der

TESTS = $(dist_check_SCRIPTS)

TESTS_ENVIRONMENT =	\
	LC_ALL="C" \
	EXEEXT=$(EXEEXT) \
	top_builddir="$(top_builddir)" \
	srcdir="$(srcdir)"

# vim: set noexpandtab:
