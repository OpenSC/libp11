# ==========================================================
# Makefile.am for PKCS#11 libp11 / engine / provider
# ==========================================================
MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
	$(srcdir)/config.h.in $(srcdir)/config.h.in~
DISTCLEANFILES = libp11.map
CLEANFILES = libp11.pc
EXTRA_DIST = Makefile.mak libp11.rc.in pkcs11.rc.in

# Headers
noinst_HEADERS= libp11-int.h pkcs11.h p11_pthread.h util.h
include_HEADERS= libp11.h p11_err.h

# Libraries to build (static-engine optional)
if ENABLE_STATIC_ENGINE
lib_LTLIBRARIES = libp11.la libpkcs11.la
else
lib_LTLIBRARIES = libp11.la
endif

enginesexec_LTLIBRARIES = pkcs11.la
pkgconfig_DATA = libp11.pc

if LIBP11_OSSL_PROVIDER
EXTRA_DIST += pkcs11prov.rc.in
providersexec_LTLIBRARIES = pkcs11prov.la
endif

SHARED_EXT=@SHARED_EXT@

# ----------------------------------------------------------
# Helper libraries
# ----------------------------------------------------------
# These helper libraries are only built (not installed) so we can
# set per-file compiler flags (e.g. -Wno-unused-parameter) for
# specific source files without affecting the rest of the project.
# ----------------------------------------------------------
# Define all non-installed helper libraries in one assignment
noinst_LTLIBRARIES = libeng_err.la libp11_err.la

# Helper library for p11_err.c
libp11_err_la_SOURCES = p11_err.c
libp11_err_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_CFLAGS) -Wno-unused-parameter

# Helper library for eng_err.c
libeng_err_la_SOURCES = eng_err.c
libeng_err_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_EXTRA_CFLAGS) $(OPENSSL_CFLAGS) \
	-Wno-unused-parameter

# ----------------------------------------------------------
# libp11 — PKCS#11 support library
# ----------------------------------------------------------
# p11_err.c is intentionally excluded from libp11_la_SOURCES
# because it is compiled as part of libp11_err.la (above).
# ----------------------------------------------------------
libp11_la_SOURCES = libpkcs11.c p11_attr.c p11_cert.c p11_ckr.c \
	p11_key.c p11_load.c p11_misc.c p11_rsa.c p11_ec.c p11_eddsa.c \
	p11_pkey.c p11_slot.c p11_front.c p11_atfork.c libp11.exports

# Compiler flags for libp11
libp11_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_CFLAGS)

# Link helper error object (libp11_err.la) and OpenSSL libraries
libp11_la_LIBADD = libp11_err.la $(OPENSSL_LIBS)

if WIN32
libp11_la_LIBADD += libp11.lo
else
dist_noinst_DATA = libp11.rc
endif

# libtool versioning
libp11_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info @LIBP11_LT_CURRENT@:@LIBP11_LT_REVISION@:@LIBP11_LT_AGE@

# Use linker version script if available, otherwise export symbols via exports file.
if HAVE_LD_VERSION_SCRIPT
libp11_la_LDFLAGS += -Wl,--version-script=libp11.map
if WIN32
libp11_la_LDFLAGS += -export-symbols "$(srcdir)/libp11.exports"
endif
else
libp11_la_LDFLAGS += -export-symbols "$(srcdir)/libp11.exports"
endif

# ----------------------------------------------------------
# PKCS#11 engine
# ----------------------------------------------------------
# eng_err.c is excluded from the pkcs11_la_SOURCES because it
# is compiled in libeng_err.la (above). We add libeng_err.la
# to pkcs11_la_LIBADD so the final engine contains the code.
# ----------------------------------------------------------
pkcs11_la_SOURCES = eng_front.c eng_back.c util_uri.c \
	engine.h eng_err.h util.h pkcs11.exports

if WIN32
pkcs11_la_SOURCES += pkcs11.rc
else
dist_noinst_DATA += pkcs11.rc
endif

# Compiler flags for PKCS#11 engine
pkcs11_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_EXTRA_CFLAGS) $(OPENSSL_CFLAGS)

# Link the helper library (libp11_err and libeng_err) plus libp11 objects and OpenSSL
pkcs11_la_LIBADD = libp11_err.la libeng_err.la $(libp11_la_OBJECTS) $(OPENSSL_LIBS)

# We intentionally not version symbols in this module because no
# application links with it. It is dynamically opened.
pkcs11_la_LDFLAGS = $(AM_LDFLAGS) -module -shared -shrext $(SHARED_EXT) \
	-avoid-version -export-symbols "$(srcdir)/pkcs11.exports"

# ----------------------------------------------------------
# PKCS#11 provider
# ----------------------------------------------------------
pkcs11prov_la_SOURCES = provider.c util_uri.c pkcs11prov.exports

if WIN32
pkcs11prov_la_SOURCES += pkcs11prov.rc
else
dist_noinst_DATA += pkcs11prov.rc
endif

# Compiler flags for PKCS#11 provider
pkcs11prov_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_EXTRA_CFLAGS) $(OPENSSL_CFLAGS)

# Link helper error object (libp11_err.la) plus libp11 objects and OpenSSL
pkcs11prov_la_LIBADD = libp11_err.la $(libp11_la_OBJECTS) $(OPENSSL_LIBS)

# We intentionally not version symbols in this module because no
# application links with it. It is dynamically opened.
pkcs11prov_la_LDFLAGS = $(AM_LDFLAGS) -module -shared -shrext $(SHARED_EXT) \
	-avoid-version -export-symbols "$(srcdir)/pkcs11prov.exports"

# ----------------------------------------------------------
# Optional static engine target (copy of pkcs11)
# ----------------------------------------------------------
if ENABLE_STATIC_ENGINE
# Create a static version of the engine as well to allow applications
# to statically link into it.
libpkcs11_la_SOURCES = $(pkcs11_la_SOURCES)
libpkcs11_la_CFLAGS = $(pkcs11_la_CFLAGS)
libpkcs11_la_LIBADD = $(pkcs11_la_LIBADD)
endif

# OpenSSL older than 1.1.0 expected libpkcs11.so instead of pkcs11.so
check-local: $(LTLIBRARIES)
	cd .libs && $(LN_S) -f pkcs11$(SHARED_EXT) libpkcs11$(SHARED_EXT)

install-exec-hook:
	cd '$(DESTDIR)$(enginesexecdir)' && $(LN_S) -f pkcs11$(SHARED_EXT) libpkcs11$(SHARED_EXT)
if LIBP11_OSSL_PROVIDER
	cd '$(DESTDIR)$(providersexecdir)' && $(LN_S) -f pkcs11prov$(SHARED_EXT) libpkcs11$(SHARED_EXT)
endif

# ----------------------------------------------------------
# Windows def file target
# ----------------------------------------------------------
if WIN32
# def file required for MS users to build library
mylibdir=$(libdir)
mylib_DATA=.libs/@WIN_LIBPREFIX@p11-@LIBP11_LT_OLDEST@.dll.def
.libs/@WIN_LIBPREFIX@p11-@LIBP11_LT_OLDEST@.dll.def:	libp11.la
endif

# ----------------------------------------------------------
# Resource compiler helpers
# ----------------------------------------------------------
RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
	$(AM_CPPFLAGS) $(CPPFLAGS)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

# .rc compilation rules
.rc.lo:
	$(LTRCCOMPILE) -i "$<" -o "$@"

.rc.o:
	$(RCCOMPILE) -i "$<" -o "$@"

# vim: set noexpandtab:
