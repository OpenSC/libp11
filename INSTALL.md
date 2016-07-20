# libp11 Installation

## Unix Build

Install the OpenSSL development package.  On Debian/Ubuntu use:

  sudo apt-get install libssl-dev

Build and install libp11:

  ./configure && make && sudo make install

## Windows Build

Download and install OpenSSL, for example the Windows builds available here:

* https://slproweb.com/products/Win32OpenSSL.html


### MSVC

To build libp11, start a Visual Studio Command Prompt and use:

  nmake -f Makefile.mak

In case your OpenSSL is installed in a different directory, use:

  nmake -f Makefile.mak OPENSSL_DIR=\your\openssl\directory
  
For x64 bit builds, make sure you opened the Native x64 VS Command Prompt and run:

  nmake /f Makefile.mak OPENSSL_DIR=c:\OpenSSL-Win64 BUILD_FOR=WIN64

If any of your builds fail for any reason, ensure you clean the src directory of obj files before re-making.

### Mingw

TODO

### Cygwin

TODO

