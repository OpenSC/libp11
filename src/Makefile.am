# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in
DISTCLEANFILES= libp11.pc
EXTRA_DIST = Makefile.mak makedef.pl

INCLUDES = $(OPENSSL_CFLAGS)

noinst_HEADERS= libp11-int.h pkcs11.h
include_HEADERS= libp11.h

lib_LTLIBRARIES = libp11.la

libp11_la_SOURCES = libpkcs11.c p11_attr.c p11_cert.c p11_err.c p11_key.c \
	p11_load.c p11_misc.c p11_ops.c p11_rsa.c p11_slot.c 

libp11_la_LDFLAGS = -version-info $(LIBP11_VERSION)
libp11_la_LIBADD = $(OPENSSL_LIBS) $(LTLIBLTDL)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libp11.pc
