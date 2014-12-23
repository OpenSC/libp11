OPENSSL_INC = /IC:\openssl\include
OPENSSL_LIB = C:\openssl\out32dll\libeay32.lib

COPTS = /Zi /MD /nologo /I..\ /I. $(OPENSSL_INC) /D_WIN32_WINNT=0x0400 /DWIN32 /DWIN32_LEAN_AND_MEAN
LINKFLAGS = /DEBUG /NOLOGO /INCREMENTAL:NO /MACHINE:IX86

TARGET                  = libp11.dll

OBJECTS                 = libpkcs11.obj p11_attr.obj p11_cert.obj p11_err.obj \
	p11_key.obj p11_load.obj p11_misc.obj p11_rsa.obj p11_ec.obj p11_slot.obj p11_ops.obj

all: $(TARGET) versioninfo.res

RSC_PROJ=/l 0x809 /r /fo"versioninfo.res"

versioninfo.res: versioninfo.rc
	rc $(RSC_PROJ) versioninfo.rc
 

.c.obj::
	cl $(COPTS) /c $<

$(TARGET): $(OBJECTS) versioninfo.res
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) \
		$(OBJECTS) $(OPENSSL_LIB) versioninfo.res
	if EXIST $*.dll.manifest mt -manifest $*.dll.manifest -outputresource:$*.dll;2

