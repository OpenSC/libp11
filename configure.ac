dnl -*- mode: m4; -*-

AC_PREREQ([2.60])

define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [2])
define([PACKAGE_VERSION_FIX], [3])

AC_INIT([libp11], [PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX-svn])
AC_CONFIG_AUX_DIR([.])
AM_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([${PACKAGE_NAME}], [${PACKAGE_VERSION}])

LIBP11_VERSION_MAJOR="PACKAGE_VERSION_MAJOR"
LIBP11_VERSION_MINOR="PACKAGE_VERSION_MINOR"
LIBP11_VERSION_FIX="PACKAGE_VERSION_FIX"

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:                      REVISION++)
#   (Oldest interface removed:          OLDEST++)
#   (Interfaces added:                  CURRENT++, REVISION=0)
LIBP11_LT_CURRENT="1"
LIBP11_LT_OLDEST="0"
LIBP11_LT_REVISION="1"
LIBP11_LT_AGE="$((${LIBP11_LT_CURRENT}-${LIBP11_LT_OLDEST}))"

AC_CONFIG_SRCDIR([src/libp11.h])

AC_CANONICAL_HOST
AC_PROG_CC
PKG_PROG_PKG_CONFIG
AC_C_BIGENDIAN

AC_MSG_CHECKING([svn checkout])
if test -e packaged; then
	svn_checkout="no"
else
	svn_checkout="yes"
fi
AC_MSG_RESULT([${svn_checkout}])

AC_ARG_WITH(
	[cygwin-native],
	[AC_HELP_STRING([--with-cygwin-native], [compile native win32])],
	,
	[with_cygwin_native="no"]
)

dnl Check for some target-specific stuff
test -z "${WIN32}" && WIN32="no"
test -z "${CYGWIN}" && CYGWIN="no"
case "${host}" in
	*-mingw32*|*-winnt*)
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
	[AC_HELP_STRING([--enable-strict], [enable strict compile mode @<:@disabled@:>@])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AC_HELP_STRING([--enable-pedantic], [enable pedantic compile mode @<:@disabled@:>@])],
	,
	[enable_pedantic="no"]
)

AC_ARG_ENABLE(
	[doc],
	[AC_HELP_STRING([--enable-doc], [enable installation of documents. @<:@disabled@:>@])],
	,
	[enable_doc="no"]
)

AC_ARG_ENABLE(
	[api-doc],
	[AC_HELP_STRING([--enable-api-doc], [enable generation and installation of api documents. @<:@disabled@:>@])],
	,
	[enable_api_doc="no"]
)

AC_ARG_WITH(
	[apidocdir],
	[AC_HELP_STRING([--with-apidocdir], [put API documents at this directory, default HTMLDIR/api])],
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
AC_LIBTOOL_WIN32_DLL
AC_LIBTOOL_RC
AC_PROG_LIBTOOL

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([ \
	errno.h fcntl.h malloc.h stdlib.h \
	inttypes.h string.h strings.h sys/time.h \
	unistd.h locale.h getopt.h dlfcn.h utmp.h \
])

AC_CHECK_PROGS([DOXYGEN],[doxygen])
test "${enable_api_doc}" = "yes" -a -z "${DOXYGEN}" && AC_MSG_ERROR([doxygen is required for api doc])

dnl These required for svn checkout
AC_ARG_VAR([XSLTPROC], [xsltproc utility])
AC_ARG_VAR([SVN], [subversion utility])
AC_ARG_VAR([WGET], [wget utility])
AC_ARG_VAR([WGET_OPTS], [wget options])
AC_ARG_VAR([TR], [tr utility])
AC_CHECK_PROGS([XSLTPROC],[xsltproc])
AC_CHECK_PROGS([SVN],[svn])
AC_CHECK_PROGS([WGET],[wget])
AC_CHECK_PROGS([TR],[tr])
test -z "${WGET_OPTS}" && WGET_OPTS="-nv"

dnl svn checkout dependencies
if test "${svn_checkout}" = "yes"; then
	AC_MSG_CHECKING([XSLTPROC requirement])
	if test -n "${XSLTPROC}"; then
		AC_MSG_RESULT([ok])
	else
		if test "${enable_doc}" = "yes"; then
			AC_MSG_ERROR([Missing XSLTPROC svn build with doc])
		else
			AC_MSG_WARN(["make dist" will not work])
		fi
	fi

	AC_MSG_CHECKING([svn doc build dependencies])
	if test -n "${SVN}" -a -n "${TR}" -a -n "${WGET}"; then
		AC_MSG_RESULT([ok])
	else
		if test "${enable_doc}" = "yes"; then
			AC_MSG_ERROR([Missing SVN, TR or WGET for svn doc build])
		else
			AC_MSG_WARN(["make dist" will not work])
		fi
	fi
fi

AC_ARG_VAR([LTLIB_CFLAGS], [C compiler flags for libltdl])
AC_ARG_VAR([LTLIB_LIBS], [linker flags for libltdl])
if test -z "${LTLIB_LIBS}"; then
	AC_CHECK_LIB(
		[ltdl],
		[lt_dlopen],
		[LTLIB_LIBS="-lltdl"],
		[AC_MSG_ERROR([ltdl not found, please install libltdl and/or libtool])]
	)

fi
saved_CFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} ${LTLIB_CFLAGS}"
AC_CHECK_HEADER(
	[ltdl.h],
	,
	[AC_MSG_ERROR([ltdl.h not found, please install libltdl and/or libtool])]
)
CFLAGS="${saved_CFLAGS}"

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
AC_SUBST([LIBP11_VERSION_MAJOR])
AC_SUBST([LIBP11_VERSION_MINOR])
AC_SUBST([LIBP11_VERSION_FIX])
AC_SUBST([LIBP11_LT_CURRENT])
AC_SUBST([LIBP11_LT_REVISION])
AC_SUBST([LIBP11_LT_AGE])
AC_SUBST([LIBP11_LT_OLDEST])
AC_SUBST([WIN_LIBPREFIX])

AM_CONDITIONAL([SVN_CHECKOUT], [test "${svn_checkout}" = "yes"])
AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])
AM_CONDITIONAL([CYGWIN], [test "${CYGWIN}" = "yes"])
AM_CONDITIONAL([ENABLE_DOC], [test "${enable_doc}" = "yes"])
AM_CONDITIONAL([ENABLE_API_DOC], [test "${enable_api_doc}" = "yes"])

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes";
	CFLAGS="${CFLAGS} -pedantic"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi

AC_OUTPUT([
	Makefile
	src/Makefile
	src/libp11.pc
	src/versioninfo.rc
	doc/Makefile
	doc/doxygen.conf
	doc/nonpersistent/Makefile
])

cat <<EOF

libp11 has been configured with the following options:


Version:                 ${PACKAGE_VERSION}
Libraries:               $(eval eval eval echo "${libdir}")

doc support:             ${enable_doc}
api doc support:         ${enable_api_doc}

Host:                    ${host}
Compiler:                ${CC}
Preprocessor flags:      ${CPPFLAGS}
Compiler flags:          ${CFLAGS}
Linker flags:            ${LDFLAGS}
Libraries:               ${LIBS}

LTLIB_CFLAGS:            ${LTLIB_CFLAGS}
LTLIB_LIBS:              ${LTLIB_LIBS}
OPENSSL_CFLAGS:          ${OPENSSL_CFLAGS}
OPENSSL_LIBS:            ${OPENSSL_LIBS}

EOF
