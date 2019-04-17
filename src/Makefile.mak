TOPDIR = ..

!INCLUDE $(TOPDIR)\make.rules.mak

LIBP11_OBJECTS = libpkcs11.obj p11_attr.obj p11_cert.obj \
	p11_err.obj p11_ckr.obj p11_key.obj p11_load.obj p11_misc.obj \
	p11_rsa.obj p11_ec.obj p11_pkey.obj p11_slot.obj p11_front.obj \
	p11_atfork.obj
LIBP11_LIB = libp11.lib
LIBP11_TARGET = libp11.dll

PKCS11_OBJECTS = eng_front.obj eng_back.obj eng_parse.obj eng_err.obj
PKCS11_TARGET = pkcs11.dll

OBJECTS = $(LIBP11_OBJECTS) $(PKCS11_OBJECTS)
TARGETS = $(LIBP11_TARGET) $(PKCS11_TARGET)

all: $(TARGETS)

clean:
	del $(OBJECTS) $(TARGETS) *.lib *.def *.res libp11.exp pkcs11.exp

.rc.res:
	rc /r /fo$@ $<

.exports.def:
	echo LIBRARY $* > $@
	echo EXPORTS >> $@
	type $< >> $@

$(LIBP11_LIB): $(LIBP11_TARGET)

$(LIBP11_TARGET): $(LIBP11_OBJECTS) $*.def $*.res
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$@ \
		$(LIBP11_OBJECTS) $(LIBS) $*.res
	if EXIST $*.dll.manifest mt -manifest $*.dll.manifest -outputresource:$*.dll;2

$(PKCS11_TARGET): $(PKCS11_OBJECTS) $(LIBP11_OBJECTS) $*.def $*.res
	link $(LINKFLAGS) /dll /def:$*.def /implib:$*.lib /out:$@ \
		$(PKCS11_OBJECTS) $(LIBP11_OBJECTS) $(LIBS) $*.res
	if EXIST $*.dll.manifest mt -manifest $*.dll.manifest -outputresource:$*.dll;2

.SUFFIXES: .exports
