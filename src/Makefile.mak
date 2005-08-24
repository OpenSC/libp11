OPENSSL_INCL_DIR = /IC:\openssl\include
OPENSSL_LIB = C:\openssl\out32dll\libeay32.lib

COPTS = /Zi /MD /nologo $(OPENSSL_INCL_DIR) /D_WIN32_WINNT=0x0400 $(OPENSSL_DEF)
LINKFLAGS = /DEBUG /NOLOGO /INCREMENTAL:NO /MACHINE:IX86

TARGET                  = libp11.dll

OBJECTS                 = p11_attr.obj p11_cert.obj p11_err.obj \
	p11_key.obj p11_load.obj p11_misc.obj p11_rsa.obj p11_slot.obj p11_ops.obj

all: $(TARGET)

.c.obj::
	cl $(COPTS) /c $<

$(TARGET): $(OBJECTS) 
	perl makedef.pl $*.def $* $(OBJECTS)
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) \
		$(OBJECTS) $(OPENSSL_LIB)
