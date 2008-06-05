AUTOMAKE_OPTIONS = foreign 1.10

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ $(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 \
	$(srcdir)/config.guess $(srcdir)/config.sub \
	$(srcdir)/aclocal/ltsugar.m4 $(srcdir)/aclocal/libtool.m4 \
	$(srcdir)/aclocal/ltversion.m4 $(srcdir)/aclocal/lt~obsolete.m4 \
	$(srcdir)/aclocal/ltoptions.m4 \
	$(srcdir)/packaged
EXTRA_DIST = svnignore

dist_noinst_DATA = COPYING bootstrap \
	$(srcdir)/examples/Makefile $(srcdir)/examples/*.c $(srcdir)/examples/README
dist_doc_DATA = NEWS

SUBDIRS = src doc

# Allow detection of packaged tarball
dist-hook:
	echo > "$(distdir)/packaged"
