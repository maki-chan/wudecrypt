# wudecrypt [![Build Status](https://travis-ci.org/maki-chan/wudecrypt.svg?branch=master)](https://travis-ci.org/maki-chan/wudecrypt)

## What is wudecrypt?
wudecrypt (sometimes also written WUDecrypt) is a tool written in C, fully cross-platform compatible, to decrypt Wii U Disk images (.wud).

**NOTE: In its current state, wudecrypt is pre-alpha quality. It could crash during the extraction of WUD images, it's not well optimized (will run slowly) and other unwanted side effects could occur. I'm not responsible for any damage wudecrypt will cause on your system.**

## How to build
Get the sources from Github and use [Bakefile](http://bakefile.org) to generate a GNU makefile that should work natively on OSX and Linux, but also via MinGW for Windows builds. You could also try to use bakefile to generate project files for Visual Studio on Windows, though I did not test VS building.

For example, to get a working build, you could run the following commands in a shell (assuming you have bakefile working as a global command):
```
$ git clone https://github.com/maki-chan/wudecrypt.git
$ cd wudecrypt
$ bkl wudecrypt.bkl
$ make
```

This will create a working `wudecrypt` executable.

## How to use
For wudecrypt to work, you will need a WUD image, the corresponding disc key and the Wii U common key. If you have all of these files, you can run wudecrypt via the following command:
```
wudecrypt path/to/image.wud /path/to/output /path/to/commonkey.bin /path/to/disckey.bin
```

wudecrypt has a fifth optional argument which can be `SI`, `UP`, `GI` or `GM` depending on which partition types you want to extract. To play the decrypted image, extracting only the `GM` type partitions should be enough. I mostly introduced this function as the extraction takes a very long time and it tries to avoid a whole lot of data you won't need.

## License
wudecrypt is released under the GNU AGPLv3 license. More information can be found in the LICENSE file or on the [original license page](https://www.gnu.org/licenses/agpl-3.0.txt).

wudecrypt uses [utarray](http://troydhanson.github.com/uthash/), published by Troy D. Hanson, licensed under the [revised BSD license](https://troydhanson.github.io/uthash/license.html)

wudecrypt uses the [SHA-1 implementation from mbed TLS](https://tls.mbed.org/sha-1-source-code), published by ARM Limited, licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
