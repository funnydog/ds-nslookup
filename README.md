# ds-nslookup

ds-nslookup is a small, self-contained and dead-simple implementation of the non-interactive mode of nslookup.

It's very limited and should be used only as a replacement for the busybox nslookup.

It uses the functions provided by libresolv to send DNS queries to a local or a remote nameserver.

### Build instructions
```
$ cd ds-nslookup
$ make
```

### Installation

```
$ make install
```

### Tests

Tested under Arch Linux x86_64 and openwrt mips 24k.

### Package for OpenWRT

To integrate this package in OpenWRT you should make a symlink to openwrt/packages.
Then you can select the package in the Network Section of menuconfig:

```
$ cd $OPENWRT
$ mkdir package/ds-nslookup
$ ln -sf $NSPATH/openwrt/Makefile package/ds-nslookup
$ make menuconfig
```

where NSPATH is the path to ds-nslookup and OPENWRT is the path to openwrt sources.
