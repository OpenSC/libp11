dnl -*- mode: m4; -*-
dnl Process this file with autoconf to produce a configure script.

# Require autoconf 2.52
AC_PREREQ(2.52)

AC_INIT(libp11, 0.0)
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
dnl see http://www.gnu.org/software/libtool/manual.html#Distributing-libltdl
AC_LIBLTDL_INSTALLABLE
AC_SUBST(LTDLINCL)
AC_SUBST(LIBLTDL)
dnl and make sure libtool knows, too
AC_LIBTOOL_DLOPEN

dnl Add libtool support.
AM_PROG_LIBTOOL
dnl Automatically update the libtool script if it becomes out-of-date.
dnl AC_SUBST(LIBTOOL_DEPS)

dnl configure libltdl
AC_CONFIG_SUBDIRS(libltdl)

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([errno.h fcntl.h malloc.h stdlib.h inttypes.h string.h strings.h sys/time.h unistd.h locale.h getopt.h dlfcn.h utmp.h])

PKG_CHECK_MODULES([OPENSSL], [openssl])

AC_OUTPUT([
Makefile
aclocal/Makefile
doc/Makefile
rsaref/Makefile
src/Makefile
src/libp11.pc
])
