dnl -*- mode: m4; -*-

AC_PREREQ([2.69])

# When bumping versions see also the LT version numbers below.
define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [4])
define([PACKAGE_VERSION_FIX], [18])
define([PACKAGE_SUFFIX], [_git])

AC_INIT([libp11],[PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([subdir-objects])

LIBP11_VERSION_MAJOR="PACKAGE_VERSION_MAJOR"
LIBP11_VERSION_MINOR="PACKAGE_VERSION_MINOR"
LIBP11_VERSION_FIX="PACKAGE_VERSION_FIX"

AC_CONFIG_SRCDIR([src/libp11.h])

# silent build by default
ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CANONICAL_HOST
AC_PROG_CC
PKG_PROG_PKG_CONFIG
AC_C_BIGENDIAN

# we need to set our soversion based on openssl's soversion to avoid
# issues with applications linking to new openssl, old libp11, and vice versa
opensslversion="$( \
	( $PKG_CONFIG --modversion --silence-errors libcrypto || \
    $PKG_CONFIG --modversion openssl ) | \
    sed 's/^\([0-9.]*\).*/\1/' )"
case "$opensslversion" in
	4.*) # Provider for OpenSSL 4.x
	    LIBP11_LT_OLDEST="4"
	    LIBP11_OSSL_PROVIDER="yes";;
	3.*) # Engines directory prefix for OpenSSL 3.x
	    LIBP11_LT_OLDEST="3"
	    LIBP11_OSSL_PROVIDER="yes"
	    debian_ssl_prefix="engines-3";;
	1.1.*) # Engines directory prefix for OpenSSL 1.1.x
	    LIBP11_LT_OLDEST="3"
	    debian_ssl_prefix="engines-1.1";;
	1.0.*) # Engines directory prefix for OpenSSL 1.0.x
	    LIBP11_LT_OLDEST="2"
	    debian_ssl_prefix="openssl-$opensslversion/engines";;
	*) # Engines directory prefix for OpenSSL 0.9.x
	    LIBP11_LT_OLDEST="2"
	    debian_ssl_prefix="ssl/engines";;
esac

case "$OSSL_PKG_VERSION" in
	3.*)
		AC_MSG_NOTICE([3.*])
		LIBP11_OSSL_PROVIDER="yes";;
esac

AM_CONDITIONAL([LIBP11_OSSL_PROVIDER], [test x$LIBP11_OSSL_PROVIDER = xyes])

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:                      REVISION++)
#   (Oldest interface removed:          OLDEST++)
#   (Interfaces added:                  CURRENT++, REVISION=0)
#
# Note that at this moment we tie the oldest (soname) version to
# the openssl version we link to. If the ABI is broken on a later
# release, we should either stick to supporting a single openssl ABI
# or bump the LT_OLDEST version sufficiently to avoid clashes.
LIBP11_LT_REVISION="3"
LIBP11_LT_CURRENT="10"
LIBP11_LT_AGE="$((${LIBP11_LT_CURRENT}-${LIBP11_LT_OLDEST}))"

gl_LD_VERSION_SCRIPT

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
		CPPFLAGS="${CPPFLAGS} -D_WIN32_WINNT=0x0600 -DWIN32_LEAN_AND_MEAN"
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
	[AS_HELP_STRING([--enable-api-doc],[enable generation and installation of API documents @<:@disabled@:>@])],
	,
	[enable_api_doc="no"]
)

AC_ARG_WITH(
	[apidocdir],
	[AS_HELP_STRING([--with-apidocdir],[put API documents at this directory @<:@HTMLDIR/api@:>@])],
	[apidocdir="${with_apidocdir}"],
	[apidocdir="\$(htmldir)/api"]
)

AC_ARG_WITH(
	[enginesdir],
	[AS_HELP_STRING([--with-enginesdir], [OpenSSL engines directory])],
	[enginesexecdir="${withval}"],
	[
		enginesexecdir="`$PKG_CONFIG --variable=enginesdir --silence-errors libcrypto`"
		if test "${enginesexecdir}" = ""; then
		    libcryptodir="`$PKG_CONFIG --variable=libdir --silence-errors libcrypto || \
			$PKG_CONFIG --variable=libdir openssl`"
		    if test -d "$libcryptodir/$debian_ssl_prefix"; then
			# Debian-based OpenSSL package (for example Ubuntu)
			enginesexecdir="$libcryptodir/$debian_ssl_prefix"
		    else # Default OpenSSL engines directory
			enginesexecdir="$libcryptodir/engines"
		    fi
		    if test "${prefix}" != "NONE" -o "${exec_prefix}" != "NONE"; then
			# Override the autodetected value with the default
			enginesexecdir="\$(libdir)"
		    fi
		fi
	]
)

AC_ARG_ENABLE(
	[static-engine],
	[AS_HELP_STRING([--enable-static-engine], [enable static engine (libpkcs11.a) build @<:@disabled@:>@])],
	,
	[enable_static_engine="no"]
)

AC_ARG_WITH(
	[modulesdir],
	[AS_HELP_STRING([--with-modulesdir], [OpenSSL3 providers directory])],
	[providersexecdir="${withval}"],
	[
		providersexecdir="`$PKG_CONFIG --variable=modulesdir --silence-errors libcrypto`"
		if test "${providersexecdir}" = ""; then
		    libcryptodir="`$PKG_CONFIG --variable=libdir --silence-errors libcrypto || \
			$PKG_CONFIG --variable=libdir openssl`"
		    if test -d "$libcryptodir/$debian_ssl_prefix"; then
			# Debian-based OpenSSL package (for example Ubuntu)
			providersexecdir="$libcryptodir/$debian_ssl_prefix"
		    else # Default OpenSSL providers directory
			providersexecdir="$libcryptodir/ossl-modules"
		    fi
		    if test "${prefix}" != "NONE" -o "${exec_prefix}" != "NONE"; then
			# Override the autodetected value with the default
			providersexecdir="\$(libdir)"
		    fi
		fi
	]
)

AC_ARG_WITH(
	[pkcs11-module],
	[AS_HELP_STRING([--with-pkcs11-module], [default PKCS11 module])],
	[pkcs11_module="${withval}"],
	[pkcs11_module="`$PKG_CONFIG --variable=proxy_module --silence-errors p11-kit-1`"])

dnl Checks for programs.
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_SED
AC_PROG_MAKE_SET

dnl Add libtool support.
LT_INIT([win32-dll])
LT_LANG([Windows Resource])

dnl Checks for header files.
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([ \
	errno.h fcntl.h malloc.h stdlib.h \
	inttypes.h string.h strings.h sys/time.h \
	unistd.h locale.h getopt.h dlfcn.h utmp.h \
])

AC_ARG_VAR([DOXYGEN], [doxygen utility])
AC_CHECK_PROGS([DOXYGEN],[doxygen])
test "${enable_api_doc}" = "yes" -a -z "${DOXYGEN}" && AC_MSG_ERROR([doxygen is required for API doc])

if test "${WIN32}" != "yes"; then
	AC_SEARCH_LIBS(
		[dlopen],
		[dl],
		,
		[AC_MSG_ERROR([dlopen required])]
	)
	AX_PTHREAD
	LIBS="$PTHREAD_LIBS $LIBS"
	CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
	CC="$PTHREAD_CC"
fi

PKG_CHECK_MODULES(
	[OPENSSL],
	[libcrypto >= 1.0.2],
	,
	[AC_MSG_ERROR([libcrypto >= 1.0.2 is required])]
)

AC_CHECK_FUNCS([ X509_get0_notAfter X509_get0_notBefore ])

if test -n "${pkcs11_module}"; then
	AC_DEFINE_UNQUOTED(
		[DEFAULT_PKCS11_MODULE],
		"${pkcs11_module}",
		[Default PKCS#11 module.])
fi

pkgconfigdir="\$(libdir)/pkgconfig"

AC_SUBST([pkgconfigdir])
AC_SUBST([apidocdir])
AC_SUBST([enginesexecdir])
AC_SUBST([providersexecdir])
AC_SUBST([LIBP11_VERSION_MAJOR])
AC_SUBST([LIBP11_VERSION_MINOR])
AC_SUBST([LIBP11_VERSION_FIX])
AC_SUBST([LIBP11_LT_CURRENT])
AC_SUBST([LIBP11_LT_REVISION])
AC_SUBST([LIBP11_LT_AGE])
AC_SUBST([LIBP11_LT_OLDEST])
AC_SUBST([WIN_LIBPREFIX])
AC_SUBST([SHARED_EXT], $(eval echo "${shrext_cmds}"))

AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])
AM_CONDITIONAL([CYGWIN], [test "${CYGWIN}" = "yes"])
AM_CONDITIONAL([ENABLE_API_DOC], [test "${enable_api_doc}" = "yes"])
AM_CONDITIONAL([ENABLE_STATIC_ENGINE], [test "${enable_static_engine}" = "yes"])

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes";
	CFLAGS="${CFLAGS} -pedantic"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi

AC_MSG_CHECKING([if libtool needs -no-undefined flag to build shared libraries])
case "$host_os" in
  cygwin*|msys*|mingw*)
    ## Add in the -no-undefined flag to LDFLAGS for libtool.
    AC_MSG_RESULT([yes])
    LDFLAGS="$LDFLAGS -no-undefined"
    ;;
  *)
    ## Don't add in anything.
    AC_MSG_RESULT([no])
    ;;
esac

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/libp11.pc
	src/libp11.rc
	src/pkcs11.rc
	src/pkcs11prov.rc
	doc/Makefile
	doc/doxygen.conf
	examples/Makefile
	tests/Makefile
	.github/workflows/ci.yml
])
AC_OUTPUT

AC_MSG_NOTICE([creating src/libp11.map])
# We do it *after* the src directory is created
rm -f src/libp11.map
echo "LIBP11_${LIBP11_LT_OLDEST}" >src/libp11.map
echo "{" >>src/libp11.map
echo "global:" >>src/libp11.map
tr '\n' ';' <$srcdir/src/libp11.exports >>src/libp11.map
echo "" >>src/libp11.map
echo "local:" >>src/libp11.map
echo '*;' >>src/libp11.map
echo "};" >>src/libp11.map
chmod ugo-w src/libp11.map

cat <<EOF

libp11 has been configured with the following options:

Version:                 ${PACKAGE_VERSION}
libp11 directory:        $(eval eval eval echo "${libdir}")
Engine directory:        ${enginesexecdir}
Provider directory:      ${providersexecdir}
Default PKCS11 module:   ${pkcs11_module}
API doc support:         ${enable_api_doc}
Static PKCS#11 engine    ${enable_static_engine}

Host:                    ${host}
Compiler:                ${CC}
Preprocessor flags:      ${CPPFLAGS}
Compiler flags:          ${CFLAGS}
Linker flags:            ${LDFLAGS}
Libraries:               ${LIBS}

OPENSSL_CFLAGS:          ${OPENSSL_CFLAGS}
OPENSSL_LIBS:            ${OPENSSL_LIBS}

EOF

# vim: set noexpandtab:
