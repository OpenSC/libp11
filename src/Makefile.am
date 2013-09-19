MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in $(srcdir)/versioninfo.rc
CLEANFILES = libp11.pc
EXTRA_DIST = Makefile.mak

noinst_HEADERS= libp11-int.h pkcs11.h
include_HEADERS= libp11.h
lib_LTLIBRARIES = libp11.la
pkgconfig_DATA = libp11.pc

libp11_la_SOURCES = libpkcs11.c p11_attr.c p11_cert.c p11_err.c p11_key.c \
	p11_load.c p11_misc.c p11_ops.c p11_rsa.c p11_ec.c p11_slot.c \
	libp11.exports
if WIN32
libp11_la_SOURCES += versioninfo.rc
else
dist_noinst_DATA = versioninfo.rc
endif
libp11_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_CFLAGS)
libp11_la_LIBADD = $(OPENSSL_LIBS)
libp11_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info @LIBP11_LT_CURRENT@:@LIBP11_LT_REVISION@:@LIBP11_LT_AGE@ \
	-export-symbols "$(srcdir)/libp11.exports" \
	-no-undefined

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

