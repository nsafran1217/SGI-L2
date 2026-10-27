# SGI's original IST tools, unmodified, runnable on a current x86 Linux:
# perl 5.6.1 and its XS modules, the scan binaries, from the IST 3.24 CD's
# RPM payloads (../ist/ist-software-extracted/IST, IST=...).
#
#   make -C ist/orig        the /stand tree in ist/orig/build/stand, and the
#                           path shim (32-bit for the tools, native for /bin/sh)
#   ist/orig/run <tool> ... run one (errdmp, superscope, scantool, ...)
#
# Needs i386 multilib: gcc -m32, /lib/ld-linux.so.2, and the i386 libc,
# libnsl and libcrypt that perl 5.6.1 links (libnsl2:i386, libcrypt1:i386).

IST  ?= ../../../ist/ist-software-extracted/IST
B    := build
# the packages that install under /stand (sysco = sysco_tools: perl 5.6.1)
PKGS := sysco sscope snxscan snxsc_l3
# Debian's libc6-dev-i386 puts the 32-bit glibc headers under the x86_64 multiarch dir
ISYSTEM32 := $(if $(wildcard /usr/include/i386-linux-gnu/bits),,-isystem /usr/include/x86_64-linux-gnu)

all: $(B)/stand/.done $(B)/lib/i386-linux-gnu/stand_shim.so $(B)/lib/x86_64-linux-gnu/stand_shim.so

$(B)/stand/.done: Makefile
	rm -rf $(B)/stand
	mkdir -p $(B)/stand
	for p in $(PKGS); do cp -R $(IST)/$$p/stand/. $(B)/stand/; done
	# the RPM hardlinks perl to perl5.6.1; the extraction left it empty
	ln -sf perl5.6.1 $(B)/stand/sysco/tools/bin/perl
	chmod -R u+w $(B)/stand
	find $(B)/stand -path '*/bin/*' -type f -exec chmod +x {} +
	chmod +x $(B)/stand/sysco/lib/*.so $(B)/stand/sysco/lib/sscope/*.so
	touch $@

$(B)/lib/i386-linux-gnu/stand_shim.so: stand_shim.c
	mkdir -p $(@D)
	$(CC) -m32 $(ISYSTEM32) -O2 -Wall -shared -fPIC -o $@ $< -ldl

$(B)/lib/x86_64-linux-gnu/stand_shim.so: stand_shim.c
	mkdir -p $(@D)
	$(CC) -O2 -Wall -shared -fPIC -o $@ $< -ldl

clean:
	rm -rf $(B)

.PHONY: all clean
