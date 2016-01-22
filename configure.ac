dnl -*- mode: m4; -*-

AC_PREREQ(2.60)

define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [3])
define([PACKAGE_VERSION_FIX], [1])
define([PACKAGE_SUFFIX], [])

AC_INIT([libp11],[PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([subdir-objects])

LIBP11_VERSION_MAJOR="PACKAGE_VERSION_MAJOR"
LIBP11_VERSION_MINOR="PACKAGE_VERSION_MINOR"
LIBP11_VERSION_FIX="PACKAGE_VERSION_FIX"

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:                      REVISION++)
#   (Oldest interface removed:          OLDEST++)
#   (Interfaces added:                  CURRENT++, REVISION=0)
LIBP11_LT_CURRENT="5"
LIBP11_LT_OLDEST="2"
LIBP11_LT_REVISION="0"
LIBP11_LT_AGE="$((${LIBP11_LT_CURRENT}-${LIBP11_LT_OLDEST}))"

AC_CONFIG_SRCDIR([src/libp11.h])

# silent build by default
ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CANONICAL_HOST
AC_PROG_CC
PKG_PROG_PKG_CONFIG
AC_C_BIGENDIAN

AC_ARG_WITH(
	[cygwin-native],
	[AS_HELP_STRING([--with-cygwin-native],[compile native win32])],
	,
	[with_cygwin_native="no"]
)

dnl Check for some target-specific stuff
test -z "${WIN32}" && WIN32="no"
test -z "${CYGWIN}" && CYGWIN="no"
case "${host}" in
	*-mingw*|*-winnt*)
		WIN32="yes"
		CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
		WIN_LIBPREFIX="lib"
	;;
	*-cygwin*)
		AC_MSG_CHECKING([cygwin mode to use])
		CYGWIN="yes"
		if test "${with_cygwin_native}" = "yes"; then
			AC_MSG_RESULT([Using native win32])
			CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
			CFLAGS="${CFLAGS} -mno-cygwin"
			WIN32="yes"
		else
			AC_MSG_RESULT([Using cygwin])
			CPPFLAGS="${CPPFLAGS} -DCRYPTOKI_FORCE_WIN32"
			WIN_LIBPREFIX="cyg"
			AC_DEFINE([USE_CYGWIN], [1], [Define if you are on Cygwin])
		fi
	;;
esac

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict],[enable strict compile mode @<:@disabled@:>@])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic],[enable pedantic compile mode @<:@disabled@:>@])],
	,
	[enable_pedantic="no"]
)

AC_ARG_ENABLE(
	[api-doc],
	[AS_HELP_STRING([--enable-api-doc],[enable generation and installation of api documents @<:@disabled@:>@])],
	,
	[enable_api_doc="no"]
)

AC_ARG_WITH(
	[apidocdir],
	[AS_HELP_STRING([--with-apidocdir],[put API documents at this directory @<:@HTMLDIR/api@:>@])],
	[apidocdir="${with_apidocdir}"],
	[apidocdir="\$(htmldir)/api"]
)

dnl Checks for programs.
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_SED
AC_PROG_MAKE_SET

dnl Add libtool support.
ifdef(
	[LT_INIT],
	[
		LT_INIT([win32-dll])
		LT_LANG([Windows Resource])
	],
	[
		AC_LIBTOOL_WIN32_DLL
		AC_LIBTOOL_RC
		AC_PROG_LIBTOOL
	]
)

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([ \
	errno.h fcntl.h malloc.h stdlib.h \
	inttypes.h string.h strings.h sys/time.h \
	unistd.h locale.h getopt.h dlfcn.h utmp.h \
])

AC_ARG_VAR([DOXYGEN], [doxygen utility])
AC_CHECK_PROGS([DOXYGEN],[doxygen])
test "${enable_api_doc}" = "yes" -a -z "${DOXYGEN}" && AC_MSG_ERROR([doxygen is required for api doc])

if test "${WIN32}" != "yes"; then
	AC_SEARCH_LIBS(
		[dlopen],
		[dl],
		,
		[AC_MSG_ERROR([dlopen required])]
	)
	AC_CHECK_FUNCS([__register_atfork],,)
fi

PKG_CHECK_MODULES(
	[OPENSSL],
	[libcrypto >= 0.9.7],
	,
	[PKG_CHECK_MODULES(
		[OPENSSL],
		[openssl >= 0.9.7],
		,
		[AC_CHECK_LIB(
			[crypto],
			[RSA_version],
			[OPENSSL_LIBS="-lcrypto"],
			[AC_MSG_ERROR([Cannot find OpenSSL])]
		)]
	)]
)

pkgconfigdir="\$(libdir)/pkgconfig"

AC_SUBST([pkgconfigdir])
AC_SUBST([apidocdir])
AC_SUBST([PTHREAD_FLAGS])
AC_SUBST([LIBP11_VERSION_MAJOR])
AC_SUBST([LIBP11_VERSION_MINOR])
AC_SUBST([LIBP11_VERSION_FIX])
AC_SUBST([LIBP11_LT_CURRENT])
AC_SUBST([LIBP11_LT_REVISION])
AC_SUBST([LIBP11_LT_AGE])
AC_SUBST([LIBP11_LT_OLDEST])
AC_SUBST([WIN_LIBPREFIX])

AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])
AM_CONDITIONAL([CYGWIN], [test "${CYGWIN}" = "yes"])
AM_CONDITIONAL([ENABLE_API_DOC], [test "${enable_api_doc}" = "yes"])

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes";
	CFLAGS="${CFLAGS} -pedantic"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/libp11.pc
	src/versioninfo.rc
	doc/Makefile
	doc/doxygen.conf
	examples/Makefile
	tests/Makefile
])
AC_OUTPUT

cat <<EOF

libp11 has been configured with the following options:


Version:                 ${PACKAGE_VERSION}
Libraries:               $(eval eval eval echo "${libdir}")

api doc support:         ${enable_api_doc}

Host:                    ${host}
Compiler:                ${CC}
Preprocessor flags:      ${CPPFLAGS}
Compiler flags:          ${CFLAGS}
Linker flags:            ${LDFLAGS}
Libraries:               ${LIBS}

PTHREAD_FLAGS:           ${PTHREAD_FLAGS}
OPENSSL_CFLAGS:          ${OPENSSL_CFLAGS}
OPENSSL_LIBS:            ${OPENSSL_LIBS}

EOF

# vim: set noexpandtab:
