
SUBDIRS = src

all::

all:: config.h

config.h: winconfig.h
	@copy /y winconfig.h config.h
	
all depend install clean::
	 @for %i in ( $(SUBDIRS) ) do \
		@cmd /c "cd %i && $(MAKE) /nologo /f Makefile.mak $@"
