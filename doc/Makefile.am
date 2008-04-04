MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

if ENABLE_DOC
SUBDIRS = nonpersistent
endif
DIST_SUBDIRS = nonpersistent

dist_doc_DATA = README
dist_noinst_DATA = $(srcdir)/doxygen-footer.html $(srcdir)/*.gif

if ENABLE_API_DOC

apidoc_DATA=api.out/html/*


api.out/html/*: \
		$(top_srcdir)/src/*.h \
		$(srcdir)/*.gif \
		doxygen.conf
	-rm -fr api.out
	$(DOXYGEN) doxygen.conf
	cp "$(srcdir)"/*.gif api.out/html

endif

clean-local:
	-rm -fr api.out
