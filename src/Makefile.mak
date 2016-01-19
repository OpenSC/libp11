TOPDIR = ..

!INCLUDE $(TOPDIR)\make.rules.mak

TARGET = libp11.dll

OBJECTS = libpkcs11.obj p11_attr.obj p11_cert.obj \
	p11_err.obj p11_key.obj p11_load.obj p11_misc.obj p11_rsa.obj \
	p11_ec.obj p11_slot.obj p11_ops.obj

all: $(TARGET) versioninfo.res

RSC_PROJ=/l 0x809 /r /fo"versioninfo.res"

versioninfo.res: versioninfo.rc
	rc $(RSC_PROJ) versioninfo.rc
 
.c.obj::
	cl $(CLFLAGS) /c $<

$(TARGET): $(OBJECTS) versioninfo.res
	echo LIBRARY $* > $*.def
	echo EXPORTS >> $*.def
	type $*.exports >> $*.def
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$(TARGET) \
		$(OBJECTS) $(LIBS) versioninfo.res
	if EXIST $*.dll.manifest mt -manifest $*.dll.manifest -outputresource:$*.dll;2
