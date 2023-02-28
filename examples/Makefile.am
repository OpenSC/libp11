AM_CFLAGS = $(OPENSSL_CFLAGS)
AM_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/src \
	-I$(top_builddir)/

EXTRA_DIST = README

noinst_PROGRAMS = auth decrypt getrandom listkeys listkeys_ext

LDADD = ../src/libp11.la $(OPENSSL_LIBS)

# vim: set noexpandtab:
