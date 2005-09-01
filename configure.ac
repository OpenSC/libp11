dnl -*- mode: m4; -*-
dnl Process this file with autoconf to produce a configure script.

# Require autoconf 2.52
AC_PREREQ(2.52)

AC_INIT(libp11, WIP)
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR(src/libp11.h)

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:                      REVISION++)
#   (Interfaces added/removed/changed:  CURRENT++, REVISION=0)
#   (Interfaces added:                  AGE++)
#   (Interfaces removed:                AGE=0)
LIBP11_VERSION=0:1:0

AC_SUBST(LIBP11_VERSION)

AC_CANONICAL_HOST
AC_PROG_CC
AC_C_BIGENDIAN

dnl Options
AM_MAINTAINER_MODE

dnl Checks for programs.
AC_PROG_CPP
AC_PROG_INSTALL

dnl use ltdl
AC_CHECK_LIB(ltdl, lt_dlopen,, [AC_MSG_ERROR([libltdl not found])])

dnl Add libtool support.
AC_PROG_LIBTOOL

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([errno.h fcntl.h malloc.h stdlib.h inttypes.h string.h strings.h sys/time.h unistd.h locale.h getopt.h dlfcn.h utmp.h ltdl.h])

PKG_CHECK_MODULES([OPENSSL], [openssl])

AC_OUTPUT([
Makefile
aclocal/Makefile
doc/Makefile
doc/doxygen.conf
rsaref/Makefile
src/Makefile
src/libp11.pc
])
