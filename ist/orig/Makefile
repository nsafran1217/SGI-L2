# SGI's original IST tools, unmodified, runnable on a current x86 Linux:
# perl 5.6.1 and its XS modules, the scan binaries, the flash tools, from
# the IST 3.24 CD's RPMs.
#
#   make ist-orig RPMS=<dir>    (from the top of the repository) or
#   make -C ist/orig RPMS=<absolute dir>
#                           unpack the RPMs in <dir> into ist/orig/build/root
#                           and build the path shim (32-bit for the tools,
#                           native for the /bin/sh they run)
#   ist/orig/run <tool> ... run one (errdmp, superscope, scantool, flashsc, ...)
#
# <dir> needs these RPMs from the CD (the newest of each is used):
#   sysco_tools (perl 5.6.1), sscope, snxscan, snxsc_l3, snxsc_firmware
#
# Needs rpm2cpio and cpio, or bsdtar; and i386 multilib: gcc -m32, and the
# i386 libc (with libnsl) and libcrypt that perl 5.6.1 links (Debian:
# gcc-multilib, libc6:i386, libcrypt1:i386; libx11-6:i386 for the GUIs).

RPMS ?= ../../../ist
B    := build
ROOT := $(B)/root
PKGS := sysco_tools sscope snxscan snxsc_l3 snxsc_firmware
# Debian's libc6-dev-i386 puts the 32-bit glibc headers under the x86_64 multiarch dir
ISYSTEM32 := $(if $(wildcard /usr/include/i386-linux-gnu/bits),,-isystem /usr/include/x86_64-linux-gnu)

# the newest <pkg>-<version>-<release>.i386.rpm of each package
rpm_of   = $(lastword $(shell ls $(RPMS)/$(1)-[0-9]*.i386.rpm 2>/dev/null | sort -V))
RPMFILES := $(foreach p,$(PKGS),$(call rpm_of,$(p)))
MISSING  := $(strip $(foreach p,$(PKGS),$(if $(call rpm_of,$(p)),,$(p))))

ifneq ($(shell command -v rpm2cpio >/dev/null && command -v cpio >/dev/null && echo y),)
unpack = rpm2cpio $(1) 2>/dev/null | (cd $(2) && cpio -idm --quiet --no-absolute-filenames)
else
unpack = bsdtar -xf $(1) -C $(2)
endif

# an explicit RPMS=, or nothing unpacked yet, needs every package
ifneq ($(MISSING),)
ifneq ($(filter command line,$(origin RPMS))$(if $(wildcard $(ROOT)/.done),,none),)
ifneq ($(MAKECMDGOALS),clean)
$(error missing RPMs in $(RPMS): $(MISSING:%=%-*.i386.rpm) (RPMS=<dir> names the directory holding the IST CD's RPMs))
endif
endif
endif

all: $(ROOT)/.done $(B)/lib/i386-linux-gnu/stand_shim.so $(B)/lib/x86_64-linux-gnu/stand_shim.so

$(ROOT)/.done: Makefile $(RPMFILES)
	rm -rf $(ROOT)
	mkdir -p $(ROOT)
	set -e; for r in $(abspath $(RPMFILES)); do \
	    echo "unpacking $${r##*/}"; $(call unpack,$$r,$(ROOT)); done
	chmod -R u+w $(ROOT)
	# The RPMs' symlinks are absolute (/usr/cpu/firmware/l2.bin ->
	# /usr/cpu/firmware/sysco/l2.bin), which the kernel resolves outside
	# the shim's mapping: point them into the tree instead.
	cd $(ROOT) && find . -type l | while read -r l; do \
	    t=$$(readlink "$$l"); case $$t in /*) \
	    ln -sfn "$$(realpath -m --relative-to="$$(dirname "$$l")" ".$$t")" "$$l";; esac; done
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
