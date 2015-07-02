EXTRA_DIST = cert.der key.der

AM_CFLAGS = $(OPENSSL_CFLAGS)
AM_CPPFLAGS = \
	-I$(top_srcdir)/ \
	-I$(top_builddir)/

AM_LDFLAGS = -no-install
LDADD = ../src/libp11.la $(OPENSSL_LIBS)

auth_SOURCES = ../examples/auth.c

check_PROGRAMS = auth
dist_check_SCRIPTS = testpkcs11.softhsm

TESTS = $(dist_check_SCRIPTS)

TESTS_ENVIRONMENT =						\
	LC_ALL="C"						\
	EXEEXT=$(EXEEXT)					\
	top_builddir="$(top_builddir)"				\
	srcdir="$(srcdir)"

