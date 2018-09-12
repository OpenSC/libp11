# libp11 Installation
The following instructions only apply to the [release tarballs.](https://github.com/OpenSC/libp11/releases)

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

### MSYS2

To build libp11, download and install msys2-i686-*.exe from https://msys2.github.io

then start a MSYS2 MSYS console from the Start menu and use:

  pacman -S git pkg-config libtool autoconf automake make gcc openssl-devel

  git clone https://github.com/OpenSC/libp11.git

  cd libp11

  autoreconf -fi

  ./configure --prefix=/usr/local

  make && make install

### Cygwin

As above, assuming that you have mentioned packages already installed.

### MINGW / MSYS

To build libp11, download and install mingw-get-setup.exe from https://sourceforge.net/projects/mingw/

I'm assuming that you have selected all necessary MINGW and MSYS packages during install 

(useful hint - after clicking at checkbox press key I).

You also need to install pkg-config or pkg-config-lite and update autoconf and openssl.

http://www.gaia-gis.it/spatialite-3.0.0-BETA/mingw_how_to.html#pkg-config

https://sourceforge.net/p/mingw/mailman/message/31908633/

https://sourceforge.net/projects/pkgconfiglite/files/

http://ftp.gnu.org/gnu/autoconf/autoconf-latest.tar.gz

https://www.openssl.org/source/

You need to configure OpenSSL to replace very old mingw's version like this:

  ./configure --prefix=/mingw threads shared mingw

  make depend && make && make install

Then download and unpack libp11, in its directory use:

  libtoolize --force

  aclocal -I m4 --install

  autoheader

  automake --force-missing --add-missing

  autoconf

  ./configure --prefix=/usr/local

  make && make install

