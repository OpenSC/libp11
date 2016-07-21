AUTOMAKE_OPTIONS = foreign 1.10
ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/configure $(srcdir)/Makefile.in \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 \
	$(srcdir)/config.guess $(srcdir)/config.sub \
	$(srcdir)/m4/ltsugar.m4 $(srcdir)/m4/libtool.m4 \
	$(srcdir)/m4/ltversion.m4 $(srcdir)/m4/lt~obsolete.m4 \
	$(srcdir)/m4/ltoptions.m4 \
	$(srcdir)/packaged
EXTRA_DIST = Makefile.mak make.rules.mak README.md

dist_noinst_DATA = COPYING INSTALL.md

dist_doc_DATA = NEWS

# Prerequisites must be first on the list
SUBDIRS = src doc examples tests

# Allow detection of packaged tarball
dist-hook:
	$(MKDIR_P) "$(distdir)/m4"
	echo > "$(distdir)/packaged"

# vim: set noexpandtab:
