#!/bin/bash

set -e

SRCDIR=.

if test -n "$1"
then
	SRCDIR="$1"
fi

test -f "$SRCDIR"/`basename $0`

if ! test -w "$SRCDIR"
then
	exit 0
fi

rm -rf "$SRCDIR"/api
mkdir "$SRCDIR"/api
cd "$SRCDIR"/..
doxygen doc/doxygen.conf

