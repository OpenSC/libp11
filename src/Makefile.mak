TOPDIR = ..

!INCLUDE $(TOPDIR)\make.rules.mak

TARGET = libp11.dll

OBJECTS = libpkcs11.obj p11_attr.obj p11_cert.obj \
	p11_err.obj p11_key.obj p11_load.obj p11_misc.obj p11_rsa.obj \
	p11_ec.obj p11_slot.obj p11_ops.obj

all: $(TARGET) libp11.res

RSC_PROJ=/l 0x809 /r /fo"libp11.res"

libp11.res: libp11.rc
	rc $(RSC_PROJ) libp11.rc
 
.c.obj::
	cl $(CLFLAGS) /c $<

$(TARGET): $(OBJECTS) libp11.res
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) \
		$(OBJECTS) $(LIBS) libp11.res
	if EXIST $*.dll.manifest mt -manifest $*.dll.manifest -outputresource:$*.dll;2
