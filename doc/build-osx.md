Mac OS X bitcoind build instructions
====================================

Authors
-------

* Laszlo Hanyecz <solar@heliacal.net>
* Douglas Huff <dhuff@jrbobdobbs.org>
* Colin Dean <cad@cad.cx>

License
-------

Copyright (c) 2009-2012 Bitcoin Developers

Distributed under the MIT/X11 software license, see the accompanying
file COPYING or http://www.opensource.org/licenses/mit-license.php.

This product includes software developed by the OpenSSL Project for use in
the OpenSSL Toolkit (http://www.openssl.org/).

This product includes cryptographic software written by
Eric Young (eay@cryptsoft.com) and UPnP software written by Thomas Bernard.

Notes
-----

See `doc/readme-qt.rst` for instructions on building Bitcoin-Qt, the
graphical user interface.

Tested on OSX 10.5 through 10.8 on Intel processors only. PPC is not
supported because it is big-endian.

All of the commands should be executed in a Terminal application. The
built-in one is located in `/Applications/Utilities`.

Preparation
-----------

You need to install XCode with all the options checked so that the compiler
and everything is available in /usr not just /Developer. XCode should be
available on your OS Xinstallation media, but if not, you can get the
current version from https://developer.apple.com/xcode/. If you install
Xcode 4.3 or later, you'll need to install its command line tools. This can
be done in `Xcode > Preferences > Downloads > Components` and generally must
be re-done or updated every time Xcode is updated.

There's an assumption that you already have `git` installed, as well. If
not, it's the path of least resistance to install Github for Mac
(OS X 10.7+) or
[Git for OS X](https://code.google.com/p/git-osx-installer/).

You will also need to install [Homebrew](http://mxcl.github.com/homebrew/)
or [MacPorts](http://www.macports.org/) in order to install library
dependencies. It's largely a religious decision which to choose, but, as of
November 2012, MacPorts is a little easier because you can just install the
dependencies immediately - no other work required. If you're unsure, read
the instructions through first in order to assess what you want to do.
Homebrew is a little more popular among those newer to OS X.

The installation of the actual dependencies is covered in the Instructions
section below.

If you are on OS X 10.7+ and choose MacPorts, you'll need to edit
`/opt/local/etc/macports/macports.conf` and uncomment "build_arch i386".

Instructions
------------

### Install dependencies

#### Install dependencies using MacPorts

Installing the dependencies using MacPorts is very straightforward.

    sudo port install boost db48 openssl miniupnpc

Optionally install `qrencode` (and set USE_QRCODE=1):

    sudo port install qrencode

#### Install dependencies using Homebrew

Installation the libraries using Homebrew takes a little more work because
we have to revert one of the installation formulas to an older version. This
step may become unnecessary in future versions of `bitcoind`.

1. Install the easy ones.

       brew install boost miniupnpc openssl

2. Revert berkeley-db formula to an older version.

       cd /usr/local
       git checkout e6a374d Library/Formula/berkeley-db.rb

3. You may have to unlink it if you've already installed the latest version.

       brew unlink berkeley-db

4. Install berkeley-db 4.8 now that you've got the right formula in place.

       brew install berkeley-db

### Building `bitcoind`

1. Clone the github tree to get the source code:

       git clone git@github.com:bitcoin/bitcoin.git bitcoin

2.  If you used Homebrew, you must modify source in order to pick up the
    `openssl` library.

    Edit the makefile.osx to change it a bit. Here's a diff that shows what
    you need to change, or you can just use this as a patch by doing
    `echo '$patch-text' | patch`, where $patch-text is the patch text below.

        diff --git a/src/makefile.osx b/src/makefile.osx
        index 9629545..ffac9a3 100644
        --- a/src/makefile.osx
        +++ b/src/makefile.osx
        @@ -7,17 +7,19 @@
         # Originally by Laszlo Hanyecz (solar@heliacal.net)

         CXX=llvm-g++
        -DEPSDIR=/opt/local
        +DEPSDIR?=/opt/local

         INCLUDEPATHS= \
          -I"$(CURDIR)" \
          -I"$(CURDIR)"/obj \
          -I"$(DEPSDIR)/include" \
        - -I"$(DEPSDIR)/include/db48"
        + -I"$(DEPSDIR)/include/db48" \
        + -I"/usr/local/Cellar/openssl/1.0.1c/include"

         LIBPATHS= \
          -L"$(DEPSDIR)/lib" \
        - -L"$(DEPSDIR)/lib/db48"
        + -L"$(DEPSDIR)/lib/db48" \
        + -L"/usr/local/Cellar/openssl/1.0.1c/lib"

         USE_UPNP:=1
         USE_IPV6:=1

3.  Build bitcoind:

        cd bitcoin/src
        make -f makefile.osx USE_IPV6=1 DEPSDIR=/usr/local

    Don't forget to add USE_QRCODE=1 if you installed `qrencode`.

Running
-------

It's now available at `./bitcoind`. We have to first create the RPC 
configuration file, though. Run `./bitcoind` to get the filename where it
should be put, or just try the below command.

    echo "rpcuser=bitcoinrpc
    rpcpassword=HdAseQSRkirfoNuUSzqzixyL9sM1T6ABfzV1nyNmbuwg" > "/Users/${USER}/Library/Application Support/Bitcoin/bitcoin.conf"
    chmod 600 "/Users/${USER}/Library/Application Support/Bitcoin/bitcoin.conf"

You should change that password to something else, though. When you run
`./bitcoind` initially before doing this step, it will generate for you an
`rpcuser` and `rpcpassword` to use.

When next you run it, it will start downloading the blockchain, but it won't
output anything while it's doing this. This process may take several hours.

Other commands:

    ./bitcoind --help  # for a list of command-line options.
    ./bitcoind -daemon # to start the bitcoin daemon.
    ./bitcoind help    # When the daemon is running, to get a list of RPC commands
