#!/bin/sh
# Copyright (c) 2025 Michał Trojnara <Michal.Trojnara@stunnel.org>

set -e # exit on errors
test_dir=testdir.$$

exit_cleanup() {
    echo "please wait while the default configuration is rebuilt"
    ./configure >/dev/null 2>/dev/null
    make >/dev/null 2>/dev/null
}

exit_success() {
    exit_cleanup
    echo
    echo "success!"
    exit 0
}

exit_failure() {
    cd ..
    exit_cleanup
    echo
    echo "$0 failed with $this_test"
    echo "results in $test_dir"
    exit 1
}

testone() {
    pkg_config_libdir=$1
    echo
    echo "************************************************************"
    echo "Testing with $pkg_config_libdir"
    echo "************************************************************"
    echo
    mkdir "$test_dir"
    cd "$test_dir"
    trap exit_failure EXIT
    PKG_CONFIG_LIBDIR=$pkg_config_libdir ../configure
    make
    # "make check" also requires also building SoftHSM2, pkcs11-tool,
    # and possibly other dependencies against that OpenSSL version.
    # LD_LIBRARY_PATH=$(dirname $pkg_config_libdir) make check
    cd ..
    trap exit_cleanup EXIT
    rm -rf "$test_dir"
}

test ! -f Makefile || make distclean

for pkg_config_libdir in /opt/openssl-[0-9]*/lib*/pkgconfig /usr/local/ssl-[0-9]*/lib*/pkgconfig; do
    test -d "$pkg_config_libdir" || continue
    openssl_version=$(echo "$pkg_config_libdir" | sed 's/.*ssl-\([0-9.]*\).*/\1/')
    awk -v "ver=$openssl_version" 'BEGIN {exit !(ver >= "1.0.2")}' || continue
    testone "$pkg_config_libdir"
done

trap exit_success EXIT
