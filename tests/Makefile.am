EXTRA_DIST = engines.cnf.in common.sh openssl-settings.sh

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
	rsa-pss-sign.softhsm \
	rsa-oaep.softhsm \
	rsa-check-privkey.softhsm \
	ec-testfork.softhsm \
	ec-evp-sign.softhsm \
	ec-check-privkey.softhsm \
	ec-cert-store.softhsm \
	ec-copy.softhsm \
	fork-change-slot.softhsm \
	case-insensitive.softhsm \
	pkcs11-uri-without-token.softhsm \
	search-all-matching-tokens.softhsm
dist_check_DATA = \
	rsa-cert.der rsa-privkey.der rsa-pubkey.der \
	ec-cert.der ec-privkey.der ec-pubkey.der

TESTS = $(dist_check_SCRIPTS)

TESTS_ENVIRONMENT =	\
	LC_ALL="C" \
	EXEEXT=$(EXEEXT) \
	PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" \
	top_builddir="$(top_builddir)" \
	srcdir="$(srcdir)"

# vim: set noexpandtab:
