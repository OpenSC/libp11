# Process this file with automake to create Makefile.in

SUBDIRS = aclocal doc src rsaref .

EXTRA_DIST = bootstrap depcomp $(shell ls examples/{README,Makefile,*.c})

MAINTAINERCLEANFILES = \
	Makefile.in config.h.in configure \
	install-sh ltmain.sh missing mkinstalldirs \
	compile depcomp config.log config.status \
	config.guess config.sub acinclude.m4 aclocal.m4

DEPCLEANFILES = config.log configure

AUTOMAKE_OPTIONS = foreign 1.5

