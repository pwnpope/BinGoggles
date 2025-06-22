## BinGoggles - Test Binaries Compilation Info

**You must install and build Buildroot inside the bingoggles/test/ directory.**

All test binaries in this directory were compiled with the following properties:

Compiler
--------
- Toolchain: Buildroot-generated
- Target triple: i686-buildroot-linux-uclibc
- C library: uClibc
- Buildroot version: 2025.05 (released June 9th, 2025)
- GCC version: 14.3.0 (from Buildroot toolchain)

Compilation Flags
-----------------
- Debug Info: Enabled (`-g`)
- Optimization: Disabled (`-O0`)

```sh
output/host/bin/i686-buildroot-linux-uclibc-gcc -g -O0 -fno-inline -fno-omit-frame-pointer \
  -Wl,--dynamic-linker=/lib/ld-uClibc.so.0 \
  -Wl,-rpath=/lib \
  -o test test.c
```