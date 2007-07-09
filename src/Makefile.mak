LIBLTDL_INC =    # E.g. /IC:\libtool-1.5.8-lib\include
LIBLTDL_LIB =     # E.g. C:\libtool-1.5.8-lib\lib\libltdl.lib

OPENSSL_INC = /IC:\openssl\include
OPENSSL_LIB = C:\openssl\out32dll\libeay32.lib

COPTS = /Zi /MD /nologo /I. $(OPENSSL_INC) $(LIBLTDL_INC) /D_WIN32_WINNT=0x0400 /DWIN32
LINKFLAGS = /DEBUG /NOLOGO /INCREMENTAL:NO /MACHINE:IX86

TARGET                  = libp11.dll

OBJECTS                 = libpkcs11.obj p11_attr.obj p11_cert.obj p11_err.obj \
	p11_key.obj p11_load.obj p11_misc.obj p11_rsa.obj p11_slot.obj p11_ops.obj

all: $(TARGET)

.c.obj::
	cl $(COPTS) /c $<

$(TARGET): $(OBJECTS) 
	perl makedef.pl $*.def $* $(OBJECTS)
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) \
		$(OBJECTS) $(OPENSSL_LIB) $(LIBLTDL_LIB)
