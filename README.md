Build state
===========

[![Build Status](https://travis-ci.org/OpenSC/libp11.png)](https://travis-ci.org/OpenSC/libp11)
[![Build status](https://ci.appveyor.com/api/projects/status/kmbu8nex5ogecoiq?svg=true)](https://ci.appveyor.com/project/LudovicRousseau/libp11)

libp11 README -- Information for developers
===========================================

This library provides a higher-level (compared to the PKCS#11 library)
interface to access PKCS#11 objects.  It is designed to integrate with
applications that use OpenSSL.

Thread-safety requires dynamic callbacks to be registered by the calling
application with the following OpenSSL functions:
* CRYPTO_set_dynlock_create_callback
* CRYPTO_set_dynlock_destroy_callback
* CRYPTO_set_dynlock_lock_callback

The wiki page for this project is at https://github.com/OpenSC/libp11/wiki
and includes a bug tracker and source browser.


Submitting pull requests
========================

For adding new features or extending functionality in addition to the code,
please also submit a test program which verifies the correctness of operation.
See tests/ for the existing test suite.

