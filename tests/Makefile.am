EXTRA_DIST = cert.der key.der common.sh

AM_CFLAGS = $(OPENSSL_CFLAGS)
AM_CPPFLAGS = \
	-I$(top_srcdir)/ \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/

AM_LDFLAGS = -no-install
LDADD = ../src/libp11.la $(OPENSSL_LIBS)

check_PROGRAMS = fork-test
dist_check_SCRIPTS = testpkcs11.softhsm testfork.softhsm testlistkeys.softhsm
dist_check_DATA = cert.der key.der pubkey.der

TESTS = $(dist_check_SCRIPTS)

TESTS_ENVIRONMENT =						\
	LC_ALL="C"						\
	EXEEXT=$(EXEEXT)					\
	top_builddir="$(top_builddir)"				\
	srcdir="$(srcdir)"

# vim: set noexpandtab:
