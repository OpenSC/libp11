MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
	$(srcdir)/config.h.in $(srcdir)/config.h.in~
CLEANFILES = libp11.pc
EXTRA_DIST = Makefile.mak libp11.rc.in pkcs11.rc.in

noinst_HEADERS= libp11-int.h pkcs11.h atfork.h
include_HEADERS= libp11.h
lib_LTLIBRARIES = libp11.la
engines_LTLIBRARIES = pkcs11.la
pkgconfig_DATA = libp11.pc

libp11_la_SOURCES = libpkcs11.c p11_attr.c p11_cert.c p11_err.c p11_key.c \
	p11_load.c p11_misc.c p11_rsa.c p11_ec.c p11_slot.c p11_front.c \
	atfork.c libp11.exports
if WIN32
libp11_la_SOURCES += libp11.rc
else
dist_noinst_DATA = libp11.rc
endif
libp11_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_CFLAGS)
libp11_la_LIBADD = $(OPENSSL_LIBS)
libp11_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info @LIBP11_LT_CURRENT@:@LIBP11_LT_REVISION@:@LIBP11_LT_AGE@ \
	-export-symbols "$(srcdir)/libp11.exports"

pkcs11_la_SOURCES = eng_front.c eng_back.c eng_parse.c engine.h pkcs11.exports
if WIN32
pkcs11_la_SOURCES += pkcs11.rc
else
dist_noinst_DATA += pkcs11.rc
endif
pkcs11_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_EXTRA_CFLAGS) $(OPENSSL_CFLAGS)
pkcs11_la_LIBADD = libp11.la $(OPENSSL_LIBS)
pkcs11_la_LDFLAGS = $(AM_LDFLAGS) -module -shared -avoid-version \
	-export-symbols "$(srcdir)/pkcs11.exports"

# OpenSSL older than 1.1.0 expected libpkcs11.so instead of pkcs11.so
all-local:
	cd .libs && $(LN_S) -f pkcs11.so libpkcs11.so
install-exec-hook:
	cd '$(DESTDIR)$(enginesdir)' && $(LN_S) -f pkcs11.so libpkcs11.so

if WIN32
# def file required for MS users to build library
mylibdir=$(libdir)
mylib_DATA=.libs/@WIN_LIBPREFIX@p11-@LIBP11_LT_OLDEST@.dll.def
.libs/@WIN_LIBPREFIX@p11-@LIBP11_LT_OLDEST@.dll.def:	libp11.la
endif

RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
	$(AM_CPPFLAGS) $(CPPFLAGS)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

.rc.lo:
	$(LTRCCOMPILE) -i "$<" -o "$@"

.rc.o:
	$(RCCOMPILE) -i "$<" -o "$@"

# vim: set noexpandtab:
