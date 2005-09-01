# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in $(HTML)

EXTRA_DIST = README export-wiki.sh export-wiki.xsl \
	generate-api.sh doxygen.conf.in $(HTML)

HTML= $(shell ls $(srcdir)/*.html $(srcdir)/*.css $(srcdir)/api/*)
