# Build state

[![Tests](https://github.com/OpenSC/libp11/actions/workflows/ci.yml/badge.svg)](https://github.com/OpenSC/libp11/actions/workflows/ci.yml)
[![Coverity Scan Status](https://scan.coverity.com/projects/15472/badge.svg)](https://scan.coverity.com/projects/opensc-libp11)


# Overview

This code repository produces two libraries:
* libp11 provides a higher-level (compared to the PKCS#11 library)
interface to access PKCS#11 objects.  It is designed to integrate with
applications that use OpenSSL.
* pkcs11 engine plugin for the OpenSSL library allows accessing
PKCS#11 modules in a semi-transparent way.

The wiki page for this project is at https://github.com/OpenSC/libp11/wiki
and includes a bug tracker and source browser.

## PKCS#11

The PKCS#11 API is an abstract API to perform operations on cryptographic objects
such as private keys, without requiring access to the objects themselves. That
is, it provides a logical separation of the keys from the operations. The
PKCS #11 API is mainly used to access objects in smart cards and Hardware or Software
Security Modules (HSMs). That is because in these modules the cryptographic keys
are isolated in hardware or software and are not made available to the applications
using them.

PKCS#11 API is an OASIS standard and it is supported by various hardware and software
vendors. Usually, hardware vendors provide a PKCS#11 module to access their devices.
A prominent example is the OpenSC PKCS #11 module which provides access to a variety
of smart cards. Other libraries like NSS or GnuTLS already take advantage of PKCS #11
to access cryptographic objects.

## OpenSSL engines

OpenSSL implements various cipher, digest, and signing features and it can
consume and produce keys. However plenty of people think that these features
should be implemented in separate hardware, like USB tokens, smart cards or
hardware security modules. Therefore OpenSSL has an abstraction layer called
"engine" which can delegate some of these features to different piece of
software or hardware.

engine_pkcs11 tries to fit the PKCS#11 API within the engine API of OpenSSL.
That is, it provides a gateway between PKCS#11 modules and the OpenSSL engine API.
One has to register the engine with OpenSSL and one has to provide the
path to the PKCS#11 module which should be gatewayed to. This can be done by editing
the OpenSSL configuration file, by engine specific controls,
or by using the p11-kit proxy module.

The p11-kit proxy module provides access to any configured PKCS #11 module
in the system. See [the p11-kit web pages](http://p11-glue.freedesktop.org/p11-kit.html)
for more information.


# PKCS #11 module configuration

## Copying the engine shared object to the proper location

OpenSSL has a location where engine shared objects can be placed
and they will be automatically loaded when requested. It is recommended
to copy the engine_pkcs11 to that location as "libpkcs11.so" to ease usage.
This is handle by 'make install' of engine_pkcs11.


## Using the engine from the command line

In systems with p11-kit-proxy engine_pkcs11 has access to all the configured
PKCS #11 modules and requires no further OpenSSL configuration.
In systems without p11-kit-proxy you need to configure OpenSSL to know about
the engine and to use OpenSC PKCS#11 module by the engine_pkcs11. For that you
add something like the following into your global OpenSSL configuration file
(often in ``/etc/ssl/openssl.cnf``).  This line must be placed at the top,
before any sections are defined:

```
openssl_conf = openssl_init
```

This should be added to the bottom of the file:

```
[openssl_init]
engines=engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/ssl/engines/libpkcs11.so
MODULE_PATH = opensc-pkcs11.so
init = 0
```

The dynamic_path value is the engine_pkcs11 plug-in, the MODULE_PATH value is
the OpenSC PKCS#11 plug-in. The engine_id value is an arbitrary identifier for
OpenSSL applications to select the engine by the identifier. In systems
with p11-kit-proxy installed and configured, you do not need to modify the
OpenSSL configuration file; the configuration of p11-kit will be used.

If you do not update the OpenSSL configuration file you will need to
specify the engine configuration explicitly. The following line loads
engine_pkcs11 with the PKCS#11 module opensc-pkcs11.so:

```
OpenSSL> engine -t dynamic -pre SO_PATH:/usr/lib/engines/engine_pkcs11.so
         -pre ID:pkcs11 -pre LIST_ADD:1 -pre LOAD 
         -pre MODULE_PATH:opensc-pkcs11.so
```


## Testing the engine operation

To verify that the engine is properly operating you can use the following example.

```
$ openssl engine pkcs11 -t
(pkcs11) pkcs11 engine
     [ available ]
```

## Using p11tool and OpenSSL from the command line

This section demonstrates how to use the command line to create a self signed
certificate for "Andreas Jellinghaus". The key of the certificate will be generated
in the token and will not exportable.

For the examples that follow, we need to generate a private key in the token and
obtain its private key URL. The following commands utilize p11tool for that.

```
$ p11tool --provider /usr/lib/opensc-pkcs11.so --login --generate-rsa --bits 1024 --label test-key
$ p11tool --provider /usr/lib/opensc-pkcs11.so --list-privkeys --login
```

Note the PKCS #11 URL shown above and use it in the commands below.

To generate a certificate with its key in the PKCS #11 module, the following commands commands
can be used. The first command creates a self signed Certificate for "Andreas Jellinghaus". The
signing is done using the key specified by the URL. The second command creates a self-signed 
certificate for the request, the private key used to sign the certificate is the same private key
used to create the request. Note that in a PKCS #11 URL you can specify the PIN using the 
"pin-value" attribute.

```
$ openssl
OpenSSL> req -engine pkcs11 -new -key "pkcs11:object=test-key;type=private;pin-value=XXXX" \
         -keyform engine -out req.pem -text -x509 -subj "/CN=Andreas Jellinghaus"
OpenSSL> x509 -engine pkcs11 -signkey "pkcs11:object=test-key;type=private;pin-value=XXXX" \
         -keyform engine -in req.pem -out cert.pem
```


## Engine controls

The supported engine controls are the following.

* **SO_PATH**: Specifies the path to the 'pkcs11-engine' shared library 
* **MODULE_PATH**: Specifies the path to the pkcs11 module shared library 
* **PIN**: Specifies the pin code 
* **DEBUG_LEVEL**: Set the debug level: 0=emerg, 1=alert, 2=crit, 3=err, 4=warning, 5=notice (default), 6=info, 7=debug
* **QUIET**: Do not print additional details 
* **LOAD_CERT_CTRL**: Load a certificate from token
* **SET_USER_INTERFACE**: Set the global user interface
* **SET_CALLBACK_DATA**: Set the global user interface extra data
* **FORCE_LOGIN**: Force login to the PKCS#11 module
* **RE_ENUMERATE**: re-enumerate the slots/tokens, required when adding/removing tokens/slots
* **VLOG_A**: Set the logging callback

An example code snippet setting specific module is shown below.

```
ENGINE_ctrl_cmd(engine, "MODULE_PATH",
		0, "/path/to/pkcs11module.so", NULL, 1);
```

In systems with p11-kit, if this engine control is not called engine_pkcs11
defaults to loading the p11-kit proxy module.


# PKCS#11 provider configuration

## PKCS#11 URI format

Only the PKCS#11 URI format defined by
[RFC 7512](https://datatracker.ietf.org/doc/html/rfc7512) is supported.

## Copying the provider shared object to the proper location

OpenSSL has a designated location where provider shared objects can be placed
for automatic loading. To simplify usage, it is recommended to copy
provider_pkcs11 to that location as `pkcs11prov.so`. This is handled by the
`make install` process of provider_pkcs11.

## Using the openssl configuration file

OpenSSL 3.x does not automatically load custom providers, so `openssl.cnf` must
explicitly define them. Without this configuration, OpenSSL will not detect or
load `pkcs11prov`.

```
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
identity = pkcs11prov
module = /usr/lib64/ossl-modules/pkcs11prov.so
pkcs11_module = /usr/lib64/opensc-pkcs11.so
debug_level = 7
force_login = 1
pin = XXXX
activate = 1
```

Some parameters can be overridden using environment variables:
`OPENSSL_MODULES`, `PKCS11_MODULE_PATH`, `PKCS11_DEBUG_LEVEL`,
`PKCS11_FORCE_LOGIN`, `PKCS11_PIN`

## Testing the provider operation

To verify that the provider is functioning correctly, run the following command:

```
$ openssl list -providers -verbose -provider pkcs11prov
Providers:
  pkcs11prov
    name: libp11 PKCS#11 provider (pkcs11prov)
    version: 3.4.1
    status: active
    build info: 3.4.1
    gettable provider parameters:
      name: pointer to a UTF8 encoded string (arbitrary size)
      version: pointer to a UTF8 encoded string (arbitrary size)
      buildinfo: pointer to a UTF8 encoded string (arbitrary size)
      status: integer (arbitrary size)

```

## Using OpenSSL with the provider from the command line

To enable automatic provider loading, ensure your `openssl.cnf` includes:

```
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
identity = pkcs11prov
pkcs11_module = /usr/lib64/opensc-pkcs11.so
activate = 1
```

To generate a certificate with its key stored in the PKCS#11 module, use:

```
$ openssl req -new -key "pkcs11:object=test-key;type=private;pin-value=XXXX" \
         -out req.pem -text -x509 -subj "/CN=Andreas Jellinghaus"
$ openssl x509 -signkey "pkcs11:object=test-key;type=private;pin-value=XXXX" \
         -in req.pem -out cert.pem
```

Alternatively, you can use environment variables:

```
$ PKCS11_MODULE_PATH=/usr/lib64/opensc-pkcs11.so PKCS11_PIN=XXXX \
         openssl req -new -key "pkcs11:object=test-key;type=private" \
         -out req.pem -text -x509 -subj "/CN=Andreas Jellinghaus" \
         -provider pkcs11prov -provider default
$ PKCS11_MODULE_PATH=/usr/lib64/opensc-pkcs11.so PKCS11_PIN=XXXX \
         openssl x509 -signkey "pkcs11:object=test-key;type=private" \
         -in req.pem -out cert.pem \
         -provider pkcs11prov -provider default
```

## Provider controls

The following provider controls are supported:
* **pkcs11_module**: Specifies the path to the PKCS#11 module shared library
* **pin**: Specifies the PIN code
* **debug_level**: Sets the debug level: 0=emerg, 1=alert, 2=crit, 3=err, 4=warning, 5=notice (default), 6=info, 7=debug
* **force_login**: Forces login to the PKCS#11 module
* **init_args**: Specifies additional initialization arguments to the PKCS#11 module

Example code snippet for setting a specific module (requires OpenSSL 3.5):

```
OSSL_PROVIDER *provider=OSSL_PROVIDER_load(NULL, "pkcs11prov");
OSSL_PROVIDER_add_conf_parameter(provider, "pkcs11_module",
		"/path/to/pkcs11module.so");
```

# Developer information

## Thread safety in libp11

libp11 internally uses OS locking, and configures the PKCS#11 module to do
the same.

Access to the the PKCS#11 tokens and objects is via a pool of PKCS#11 sessions.
This allows concurrent usage of crypto operations in thread safe manner.

## Submitting pull requests

For adding new features or extending functionality in addition to the code,
please also submit a test program which verifies the correctness of operation.
See tests/ for the existing test suite.
