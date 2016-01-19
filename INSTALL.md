# libp11 Installation

## Unix Build

Install the OpenSSL development package.  On Debian/Ubuntu use:

  sudo apt-get install libssl-dev

Build and install libp11:

  ./configure && make && sudo make install

## Windows Build

Download and install OpenSSL, for example:

* https://slproweb.com/download/Win32OpenSSL-1_0_2e.exe
* https://slproweb.com/download/Win64OpenSSL-1_0_2e.exe

### MSVC

To build libp11 use:

  nmake -f Makefile.mak

In case your OpenSSL is installed in a different directory, use:

  nmake -f Makefile.mak OPENSSL_DIR=\your\openssl\directory

### Mingw

TODO

### Cygwin

TODO

