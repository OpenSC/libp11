MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

dist_doc_DATA = 
dist_noinst_DATA = $(srcdir)/doxygen-footer.html $(srcdir)/*.gif

if ENABLE_API_DOC

apidoc_DATA=api.out/html/*

api.out/html/*: api.out
api.out:	$(top_srcdir)/src/*.h \
		$(srcdir)/*.gif \
		doxygen.conf
	-rm -fr api.out
	$(DOXYGEN) doxygen.conf
	cp "$(srcdir)"/*.gif api.out/html

endif

clean-local:
	-rm -fr api.out

# vim: set noexpandtab:
