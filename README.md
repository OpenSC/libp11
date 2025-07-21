# Build state

[![Tests](https://github.com/OpenSC/libp11/actions/workflows/ci.yml/badge.svg)](https://github.com/OpenSC/libp11/actions/workflows/ci.yml)
[![Coverity Scan Status](https://scan.coverity.com/projects/15472/badge.svg)](https://scan.coverity.com/projects/opensc-libp11)

# Table of contents
- [Overview](#overview)
- [PKCS#11 provider configuration](#pkcs11-provider-configuration)
- [PKCS#11 engine configuration](#pkcs11-engine-configuration)
- [Developer information](#developer-information)

# Overview

This code repository provides three libraries:
* libp11 – Provides a higher-level interface (compared to the PKCS#11 library)
  for accessing PKCS#11 objects. It is designed to integrate with applications
  that use OpenSSL.
* pkcs11prov – An OpenSSL 3.x provider plugin that allows transparent access to
  PKCS#11 modules.
* pkcs11 – A legacy OpenSSL engine plugin that allows semi-transparent access
  to PKCS#11 modules.

The wiki page for this project is available at
https://github.com/OpenSC/libp11/wiki. It includes a bug tracker and source
browser.

## PKCS#11

The PKCS#11 API is an abstract API to perform operations on cryptographic
objects such as private keys, without requiring access to the objects
themselves. That is, it provides a logical separation of the keys from the
operations. The PKCS#11 API is mainly used to access objects in smart cards and
hardware or software security modules (HSMs). In these modules, cryptographic
keys are isolated and not made available to applications.

The PKCS#11 API is an OASIS standard and is supported by various hardware and
software vendors. Hardware vendors usually provide a PKCS#11 module to access
their devices. A prominent example is the OpenSC PKCS#11 module which provides
access to a variety of smart cards. Other libraries, such as NSS and GnuTLS,
already take advantage of PKCS#11 to access cryptographic objects.

For further integration with multiple PKCS#11 modules, the
[p11-kit](https://p11-glue.github.io/p11-glue/p11-kit/manual/) proxy module can
be used in conjunction with the pkcs11prov provider and the pkcs11 engine,
allowing access to all PKCS#11 modules configured on the system.

## OpenSSL providers

With OpenSSL 3.x, the architecture has been redesigned to use a provider-based
model. In this model, most cryptographic algorithms and related functionality
are implemented in providers, which are dynamically loadable modules. Providers
can supply implementations of ciphers, digests, key management, and related
operations.

The **pkcs11prov** provider is designed to bridge the OpenSSL provider
interface and the PKCS#11 API. This enables applications using OpenSSL 3.x to
transparently access cryptographic operations and objects managed by PKCS#11
modules, such as those found in smart cards, USB tokens, and hardware security
modules. The provider registers itself with OpenSSL, and the specific PKCS#11
module to be used is typically specified in the OpenSSL configuration file or
via provider-specific parameters.

By using the pkcs11prov provider, applications can perform cryptographic
operations using keys stored in external hardware, without requiring changes to
application code.

## OpenSSL engines

OpenSSL implements various cipher, digest, and signing features and it can
consume and produce keys. However, many people believe that these features
should be implemented in separate hardware, such as USB tokens, smart cards, or
hardware security modules. Therefore, OpenSSL includes an abstraction layer
called an "engine", which can delegate some of these features to different
pieces of software or hardware.

The **pkcs11 engine** integrates the PKCS#11 API within the OpenSSL engine API.
That is, it provides a gateway between PKCS#11 modules and the OpenSSL engine
API. The engine must be registered with OpenSSL, and the path to the PKCS#11
module, which will perform cryptographic operations, must be specified. This
can be done by editing the OpenSSL configuration file or using engine-specific
controls.


# PKCS#11 provider configuration

## PKCS#11 URI format

The provider supports most of the PKCS#11 URI format defined by
[RFC 7512](https://datatracker.ietf.org/doc/html/rfc7512).

## Copying the provider shared object to the proper location

OpenSSL has a designated location where provider shared objects can be placed
to allow automatic loading. To simplify usage, it is recommended to copy
pkcs11prov to that location as `pkcs11prov.so`.

The provider location can be displayed with:

```
openssl version -m
```

`make install` in libp11 handles provider installation.

## Using the OpenSSL configuration file

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
pkcs11_module = /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so
debug_level = 7
force_login = 1
pin = XXXX
activate = 1
```

Some parameters can be overridden using environment variables:
`OPENSSL_MODULES`, `PKCS11_MODULE_PATH`, `PKCS11_DEBUG_LEVEL`,
`PKCS11_FORCE_LOGIN`, `PKCS11_PIN`

## Testing the provider operation

To verify correct provider operation, run the following command:

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

To enable automatic provider loading, ensure your `openssl.cnf` includes the
following:

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
pkcs11_module = /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so
activate = 1
```

To generate a certificate with its key stored in the PKCS#11 module, use the
following:

```
$ openssl req -new -key "pkcs11:object=test-key;type=private;pin-value=XXXX" \
         -out req.pem -text -x509 -subj "/CN=Andreas Jellinghaus"
$ openssl x509 -signkey "pkcs11:object=test-key;type=private;pin-value=XXXX" \
         -in req.pem -out cert.pem
```

Alternatively, use environment variables:

```
$ PKCS11_MODULE_PATH=/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so PKCS11_PIN=XXXX \
         openssl req -new -key "pkcs11:object=test-key;type=private" \
         -out req.pem -text -x509 -subj "/CN=Andreas Jellinghaus" \
         -provider pkcs11prov -provider default
$ PKCS11_MODULE_PATH=/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so PKCS11_PIN=XXXX \
         openssl x509 -signkey "pkcs11:object=test-key;type=private" \
         -in req.pem -out cert.pem \
         -provider pkcs11prov -provider default
```

## Provider controls

The provider supports the following controls:
* **pkcs11_module**: Specifies the path to the PKCS#11 module shared library
* **pin**: Specifies the PIN
* **debug_level**: Sets the debug level: 0=emerg, 1=alert, 2=crit, 3=err,
  4=warning, 5=notice (default), 6=info, 7=debug
* **force_login**: Forces login to the PKCS#11 module
* **init_args**: Specifies additional initialization arguments to the PKCS#11
  module

Example code snippet for setting a specific module (requires OpenSSL 3.5):

```
OSSL_PROVIDER *provider=OSSL_PROVIDER_load(NULL, "pkcs11prov");
OSSL_PROVIDER_add_conf_parameter(provider, "pkcs11_module",
		"/path/to/pkcs11module.so");
```


# PKCS#11 engine configuration

## Copying the engine shared object to the proper location

OpenSSL has a designated location where engine shared objects can be placed,
and they will be automatically loaded when requested. It is recommended to
copy the pkcs11 engine to that location as `libpkcs11.so` to simplify usage.

The engine location can be displayed with:

```
openssl version -e
```

`make install` in libp11 handles engine installation.

## Using the engine from the command line

On systems with p11-kit-proxy, the pkcs11 engine has access to all the
configured PKCS#11 modules and requires no further OpenSSL configuration. In
systems without p11-kit-proxy, you need to configure OpenSSL to recognize the
engine and to use the OpenSC PKCS#11 module with the pkcs11 engine. Add the
following line to your global OpenSSL configuration file (often in
`/etc/ssl/openssl.cnf`). Place this line at the top, before any sections are
defined:

```
openssl_conf = openssl_init
```

Add the following at the end of the file:

```
[openssl_init]
engines=engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so
MODULE_PATH = opensc-pkcs11.so
init = 0
```

The `dynamic_path` value is the pkcs11 engine plug-in. The `MODULE_PATH` value
is the OpenSC PKCS#11 plug-in. The `engine_id` value is an arbitrary identifier
for OpenSSL applications to select the engine by the identifier. On systems
with p11-kit-proxy installed and configured, you do not need to modify the
OpenSSL configuration file; the configuration of p11-kit will be used. If you
do not update the OpenSSL configuration file, you must specify the engine
configuration explicitly. The following line loads the pkcs11 engine with the
PKCS#11 module opensc-pkcs11.so:

```
OpenSSL> engine -t dynamic
         -pre SO_PATH:/usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so
         -pre ID:pkcs11 -pre LIST_ADD:1 -pre LOAD
         -pre MODULE_PATH:opensc-pkcs11.so
```

## Testing the engine operation

To verify that the engine is properly operating, use the following example:

```
$ openssl engine pkcs11 -t
(pkcs11) pkcs11 engine
     [ available ]
```

## Using p11tool and OpenSSL from the command line

This section demonstrates how to use the command line to create a self-signed
certificate for "Andreas Jellinghaus". The key of the certificate will be
generated in the token and will not be exportable.

For the examples that follow, we need to generate a private key in the token
and obtain its private key URL. The following commands use `p11tool` for this
purpose.

```
$ p11tool --provider /usr/lib/opensc-pkcs11.so --login --generate-rsa --bits 1024 --label test-key
$ p11tool --provider /usr/lib/opensc-pkcs11.so --list-privkeys --login
```

Note the PKCS#11 URL shown above and use it in the commands below.

To generate a certificate with its key in the PKCS#11 module, use the following
commands. The first command creates a self-signed certificate for "Andreas
Jellinghaus". Signing is performed using the key specified by the URL. The
second command creates a self-signed certificate for the request, the private
key used to sign the certificate is the same private key used to create the
request. Note that, in a PKCS#11 URL, you can specify the PIN using the
"pin-value" attribute.

```
$ openssl
OpenSSL> req -engine pkcs11 -new -key "pkcs11:object=test-key;type=private;pin-value=XXXX" \
         -keyform engine -out req.pem -text -x509 -subj "/CN=Andreas Jellinghaus"
OpenSSL> x509 -engine pkcs11 -signkey "pkcs11:object=test-key;type=private;pin-value=XXXX" \
         -keyform engine -in req.pem -out cert.pem
```

## Engine controls

The following engine controls are supported:

* **SO_PATH**: Specifies the path to the 'pkcs11-engine' shared library
* **MODULE_PATH**: Specifies the path to the pkcs11 module shared library
* **PIN**: Specifies the PIN
* **DEBUG_LEVEL**: Set the debug level: 0=emerg, 1=alert, 2=crit, 3=err,
  4=warning, 5=notice (default), 6=info, 7=debug
* **QUIET**: Do not print additional details
* **LOAD_CERT_CTRL**: Load a certificate from token
* **SET_USER_INTERFACE**: Set the global user interface
* **SET_CALLBACK_DATA**: Set the global user interface extra data
* **FORCE_LOGIN**: Force login to the PKCS#11 module
* **RE_ENUMERATE**: re-enumerate the slots/tokens, required when
  adding/removing tokens/slots
* **VLOG_A**: Set the logging callback

The following example demonstrates how to set a specific module:

```
ENGINE_ctrl_cmd(engine, "MODULE_PATH",
		0, "/path/to/pkcs11module.so", NULL, 1);
```

On systems with p11-kit, if this engine control is not called, the pkcs11 engine
defaults to loading the p11-kit proxy module.


# Developer information

## Thread safety in libp11

libp11 internally uses OS locking, and configures the PKCS#11 module to do
the same.

Access to PKCS#11 tokens and objects is provided via a pool of PKCS#11
sessions. This allows concurrent usage of crypto operations in a thread-safe
manner.

## Submitting pull requests

When adding new features or extending functionality, please also submit a test program that verifies correct operation.

Refer to the `tests/` directory for the existing test suite.
