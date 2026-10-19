# SGI L2 controller tools for current systems (from the reconstruction of
# SGI's snxsc_l3 1.62.0).
#
#   make            build everything into build/ (native)
#   make test       layout checks: every SGI struct as in the original i386 binaries
#   make check      unit tests, and every session test (l2cmd, l2term, consoles, L1,
#                   l2gui) against this build: outputs must match tests/golden/
#   make golden     rewrite tests/golden/ from this build (review the diff!)
#   make interop    the session tests with SGI's original binaries as well (needs
#                   ../ist or ORIG_BIN): old clients against this l2, and the reverse
#   make check-all  check for the native, 32-bit and ASan builds (check-s390x: big-endian)
#   make clean
#
# l2gui also needs FLTK, built from ../refs/fltk by ../retools/setup_fltk.sh
# (32 or 64 to match ARCH); without it l2gui is skipped. FLTK_CONFIG=<fltk-config>
# selects another FLTK 1.3/1.4 build.
#
# ARCH=-m32 B=build32 builds with the original binaries' struct layouts.

CC      ?= gcc
ARCH    ?=
CFLAGS  ?= -g -O0
# -fsigned-char: the code was written for i386, where char is signed (not so on
# s390x, ARM, PowerPC)
CFLAGS  += $(ARCH) -std=gnu99 -fcommon -fno-strict-aliasing -fno-builtin-fprintf -include compat/printf_check.h -fsigned-char -Icompat -Wall -Wextra -Wno-unused-parameter -Wno-format-zero-length
# Debian's libc6-dev-i386 puts the 32-bit glibc headers under the x86_64 multiarch dir
ISYSTEM32 := $(if $(wildcard /usr/include/i386-linux-gnu/bits),,-isystem /usr/include/x86_64-linux-gnu)
ifeq ($(ARCH),-m32)
ISYSTEM := $(ISYSTEM32)
CFLAGS  += $(ISYSTEM)
endif
# the tree builds warning-free with gcc 14; WERROR= for other compilers
WERROR  ?= -Werror
CFLAGS  += $(WERROR)
LDFLAGS += $(ARCH) $(EXTRA_LDFLAGS)
CFLAGS  += $(EXTRA_CFLAGS)   # e.g. EXTRA_CFLAGS=-fsanitize=address EXTRA_LDFLAGS=-fsanitize=address
B       := build

LIB_SRCS := \
	sys_ctrl/common/sys/l3paths.c \
	sys_ctrl/common/IRouter/IRouter.c \
	sys_ctrl/common/IRouter/IRouter2Router.c \
	sys_ctrl/common/Router/Buff.c \
	sys_ctrl/common/Router/Event.c \
	sys_ctrl/common/Router/Router.c \
	sys_ctrl/common/Router/RouterCl.c \
	sys_ctrl/common/Router/Socket.c \
	sys_ctrl/common/Router/SocketIO.c \
	sys_ctrl/common/main/L2Cfg.c \
	sys_ctrl/common/sys/BuffWrite.c \
	sys_ctrl/common/sys/Logger.c \
	sys_ctrl/common/sys/MemUsage.c \
	sys_ctrl/common/sys/brick_types.c \
	sys_ctrl/l3/IRouter/IRouterL3.c \
	sys_ctrl/l3/api/SCapi.c \
	sys_ctrl/l3/api/SCapiL2.c \
	sys_ctrl/l3/main/settings.c \
	sys_ctrl/l3/main/l2log.c \
	sys_ctrl/l3/sys/syslogLib.c

L2_SRCS := \
	sys_ctrl/l3/l2/l2.c \
	sys_ctrl/l3/l2/l1.c \
	sys_ctrl/l3/l2/l1net.c \
	sys_ctrl/l3/l2/serial.c \
	sys_ctrl/l3/l2/smp.c \
	sys_ctrl/l3/l2/enet.c \
	sys_ctrl/l3/l2/cfg.c \
	sys_ctrl/l3/l2/l2cmd.c \
	sys_ctrl/l3/l2/cmd.c \
	sys_ctrl/l3/l2/broadcast.c \
	sys_ctrl/l3/l2/target.c \
	sys_ctrl/l3/l2/lpbk.c \
	sys_ctrl/l3/l2/dmp.c \
	sys_ctrl/l3/l2/dest.c \
	sys_ctrl/l3/l2/reqrspq.c \
	sys_ctrl/l3/l2/format.c \
	sys_ctrl/l3/l2/power.c \
	sys_ctrl/l3/l2/irtr.c \
	sys_ctrl/l3/l2/discover.c \
	sys_ctrl/l3/l2/route.c \
	sys_ctrl/common/main/EnetServer.c \
	sys_ctrl/common/Router/RouterSv.c \
	sys_ctrl/common/sys/Cmd.c \

L2TERM_SRCS := \
	sys_ctrl/l3/utils/l2term.c \
	sys_ctrl/l3/main/SysCfg.c \
	sys_ctrl/l3/api/SCapiConn.c

L2CMD_SRCS := \
	sys_ctrl/l3/utils/l2cmd.c

L2GUI_SRCS := \
	sys_ctrl/l3/gui/mainwin.cc \
	sys_ctrl/l3/gui/logowin.cc \
	sys_ctrl/l3/gui/destwin.cc \
	sys_ctrl/l3/gui/graphwin.cc \
	sys_ctrl/l3/gui/cmdwin.cc \
	sys_ctrl/l3/gui/l2gui.cc \
	sys_ctrl/l3/gui/config.cc \
	sys_ctrl/l3/gui/l2comm.cc \
	sys_ctrl/l3/gui/flboxtype.cc
L2GUI_CSRCS := \
	sys_ctrl/l3/main/SysCfg.c \
	sys_ctrl/l3/api/SCapiConn.c \
	sys_ctrl/common/sys/Cmd.c
L2GUI_UI := mainwin logowin destwin graphwin cmdwin

# FLTK for l2gui. Its -D_FILE_OFFSET_BITS=64 is left out: the GUI shares
# structs with libsgi.a, which is built without it.
FLTK_BITS   := $(if $(filter -m32,$(ARCH)),32,64)
FLTK_CONFIG ?= $(abspath ../tools/fltk/release-1.3.8-$(FLTK_BITS)/bin/fltk-config)
FLUID       ?= $(dir $(FLTK_CONFIG))fluid
# (native builds only: a cross build, with QEMU set, has no FLTK for its target)
WITH_L2GUI  := $(if $(QEMU),,$(wildcard $(FLTK_CONFIG)))
ifneq ($(WITH_L2GUI),)
FLTK_CXXFLAGS := $(patsubst -I%,-isystem %,$(filter-out -D_FILE_OFFSET_BITS% -D_LARGEFILE%,\
                   $(shell $(FLTK_CONFIG) --cxxflags)))
FLTK_LDFLAGS  := $(if $(filter 32,$(FLTK_BITS)),-L$(abspath ../tools/fltk/i386-lib)) \
                 $(shell $(FLTK_CONFIG) --ldstaticflags)
endif
CXXFLAGS ?= -g -O0
CXXFLAGS += $(ARCH) -fno-strict-aliasing -fsigned-char -Icompat -Wall -Wextra -Wno-unused-parameter -Wno-format-zero-length -Wno-write-strings \
            -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-function \
            $(ISYSTEM) $(FLTK_CXXFLAGS) $(WERROR) $(EXTRA_CFLAGS)


LIB_OBJS := $(LIB_SRCS:%.c=$(B)/%.o)
TOOLS    := l2 l2term l2cmd
ifneq ($(WITH_L2GUI),)
TOOLS    += l2gui
else ifeq ($(QEMU),)
$(info l2gui skipped: no $(FLTK_CONFIG) (run ../retools/setup_fltk.sh $(FLTK_BITS)))
endif

.PHONY: all test check check-all check-s390x difftest golden interop clean
all: $(TOOLS:%=$(B)/bin/%)

$(B)/%.o: %.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(shell find $(B) -name '*.d' 2>/dev/null)

# FLUID output goes to $(B)/gen; each gui/X.cc includes its "ui/X.cxx"
UI_GEN := $(foreach u,$(L2GUI_UI),$(B)/gen/sys_ctrl/l3/gui/ui/$(u).cxx)
$(B)/gen/sys_ctrl/l3/gui/ui/%.cxx: sys_ctrl/l3/gui/ui/%.fl $(wildcard sys_ctrl/l3/gui/ui/images/*)
	@mkdir -p $(dir $@)
	cd $(dir $@) && $(FLUID) -c -o $*.cxx -h $*.h $(abspath $<)

$(B)/sys_ctrl/l3/gui/%.o: sys_ctrl/l3/gui/%.cc $(UI_GEN) Makefile
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -I$(B)/gen/sys_ctrl/l3/gui -MMD -MP -c $< -o $@

# (anew each time: ar keeps the members of deleted sources)
$(B)/libsgi.a: $(LIB_OBJS)
	rm -f $@
	$(AR) rcs $@ $^

$(B)/bin/l2: $(L2_SRCS:%.c=$(B)/%.o) $(B)/libsgi.a
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(B)/bin/l2term: $(L2TERM_SRCS:%.c=$(B)/%.o) $(B)/libsgi.a
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(B)/bin/l2cmd: $(L2CMD_SRCS:%.c=$(B)/%.o) $(B)/libsgi.a
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(B)/bin/l2gui: $(L2GUI_SRCS:%.cc=$(B)/%.o) $(L2GUI_CSRCS:%.c=$(B)/%.o) $(B)/libsgi.a
	@mkdir -p $(dir $@)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) $(FLTK_LDFLAGS) -o $@

# Cross builds: QEMU='qemu-s390x -L <sysroot>' also writes $(B)/qemu-bin/ wrappers,
# for running the tests with NEW_BIN=$PWD/$(B)/qemu-bin (see README.md)
ifneq ($(QEMU),)
all: $(TOOLS:%=$(B)/qemu-bin/%)
$(B)/qemu-bin/%: $(B)/bin/%
	@mkdir -p $(dir $@)
	printf '#!/bin/sh\nexec %s %s "$$@"\n' '$(QEMU)' '$(abspath $<)' > $@
	chmod +x $@
endif

# (always 32-bit: the layouts checked are the original i386 binaries')
test:
	$(CC) $(CFLAGS) -m32 $(ISYSTEM32) -fsyntax-only tests/layout_check.c
	@echo "layout check passed"

# make check: the unit tests and every session test against this build (B=;
# cross builds run through their qemu wrappers). The unit tests compare
# modules with the faithful reconstruction (RECON_REF, default origin/main:
# the src repository's main) and are skipped without it.
# make check-all: the native, 32-bit and ASan builds; make check-s390x the
# big-endian one.
CHECK_BIN  = $(abspath $(B))/$(if $(QEMU),qemu-bin,bin)
RECON_REF ?= origin/main
# (l2cfg_test links a 64-bit libsgi.a: this build's, if it is a plain native one)
UNIT_LIBSGI = $(if $(ARCH)$(EXTRA_CFLAGS),,LIBSGI=$(abspath $(B))/libsgi.a)
SESSION_TESTS = tests/difftest.sh tests/l2term_test.py tests/smp_test.py \
	tests/l1net_test.py tests/l1_test.py tests/l1usb_test.py tests/options_test.sh \
	tests/l2_options_test.py $(if $(filter l2gui,$(TOOLS)),tests/l2gui_test.py)
check: all
	$(if $(QEMU),,@if git rev-parse -q --verify $(RECON_REF) >/dev/null; then \
	    for t in tests/unit/*_test.sh; do RECON_REF=$(RECON_REF) $(UNIT_LIBSGI) $$t || exit 1; done; \
	else echo "SKIP  unit tests: no $(RECON_REF) (the faithful reconstruction) in git"; fi)
	@fail=0; for t in $(SESSION_TESTS); do NEW_BIN=$(CHECK_BIN) $$t || fail=1; done; exit $$fail

difftest: check

golden: all
	@for t in $(SESSION_TESTS); do GOLDEN=update NEW_BIN=$(CHECK_BIN) $$t || exit 1; done
	git status --short tests/golden

interop: all
	@fail=0; for t in $(SESSION_TESTS); do \
	    INTEROP=1 NEW_BIN=$(CHECK_BIN) $$t || fail=1; done; exit $$fail

S390X := $(abspath ../tools/s390x/root/usr)
check-all:
	$(MAKE) check
	$(MAKE) check ARCH=-m32 B=build32
	ASAN_OPTIONS=detect_leaks=0 $(MAKE) check ARCH=-m64 B=build64asan \
	    EXTRA_CFLAGS=-fsanitize=address EXTRA_LDFLAGS=-fsanitize=address

# big-endian (slow; byte order was settled before the rewrite): after
# ../retools/setup_s390x.sh
check-s390x:
	PATH=$(S390X)/bin:$$PATH LD_LIBRARY_PATH=$(S390X)/lib/x86_64-linux-gnu $(MAKE) check \
	    CC=s390x-linux-gnu-gcc-14 AR=s390x-linux-gnu-ar ARCH= B=builds390x \
	    QEMU="$(S390X)/bin/qemu-s390x -L $(S390X)/s390x-linux-gnu"

clean:
	rm -rf $(B)
