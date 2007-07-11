dnl -*- mode: m4; -*-
dnl Process this file with autoconf to produce a configure script.

# Require autoconf 2.52
AC_PREREQ(2.52)

AC_INIT(libp11, [0.2.3-svn])

AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR(src/libp11.h)

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:                      REVISION++)
#   (Interfaces added/removed/changed:  CURRENT++, REVISION=0)
#   (Interfaces added:                  AGE++)
#   (Interfaces removed:                AGE=0)
LIBP11_VERSION=1:1:1

AC_SUBST(LIBP11_VERSION)

AC_CANONICAL_HOST
AC_PROG_CC
AC_C_BIGENDIAN

dnl Options
AM_MAINTAINER_MODE

dnl Checks for programs.
AC_PROG_CPP
AC_PROG_INSTALL

dnl Add libtool support.
AC_PROG_LIBTOOL

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([errno.h fcntl.h malloc.h stdlib.h inttypes.h string.h strings.h sys/time.h unistd.h locale.h getopt.h dlfcn.h utmp.h])

dnl use ltdl
AC_LIB_LINKFLAGS(ltdl)

saved_LIBS="$LIBS"
LIBS="$saved_LIBS $LIBLTDL"
AC_CHECK_HEADER([ltdl.h], [AC_MSG_RESULT([yes])],
   [ AC_MSG_ERROR([ltdl.h not found, please install libltdl and/or libtool]) ])
LIBS="$saved_LIBS"

PKG_CHECK_MODULES(OPENSSL, [openssl])

AC_OUTPUT([
Makefile
aclocal/Makefile
doc/Makefile
doc/doxygen.conf
src/Makefile
src/libp11.pc
])
