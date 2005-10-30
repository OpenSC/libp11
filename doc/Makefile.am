# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in $(HTML) ChangeLog

EXTRA_DIST = README export-wiki.sh export-wiki.xsl \
	generate-api.sh doxygen.conf.in $(HTML) index.html ChangeLog

HTML= $(shell ls $(srcdir)/*.html $(srcdir)/*.css $(srcdir)/api/*)

index.html:
	sh $(srcdir)/export-wiki.sh $(srcdir)
	sh $(srcdir)/generate-api.sh $(srcdir)

ChangeLog:
	sh $(srcdir)/changelog.sh $(srcdir)
