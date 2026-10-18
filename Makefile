# Reconstructed SGI L3 system-controller tools.
#
#   make            build everything into build/ (32-bit, matching the original ABI)
#   make test       layout checks: every SGI struct must match the original binaries
#   make check      every differential test (l2cmd, l2term, NVRAM, L1, l2gui sessions)
#                   against this build: outputs must match the original binaries'
#   make check-all  the same for the 32-bit, 64-bit, ASan and s390x builds
#   make clean
#
# l2gui also needs FLTK, built from ../refs/fltk by ../retools/setup_fltk.sh
# (32 or 64 to match ARCH); without it l2gui is skipped. FLTK_CONFIG=<fltk-config>
# selects another FLTK 1.3/1.4 build.
#
# ARCH=-m32 keeps struct layouts identical to the originals (checked by make test).

CC      ?= gcc
ARCH    ?= -m32
CFLAGS  ?= -g -O0
# -fsigned-char: the code was written for i386, where char is signed (not so on
# s390x, ARM, PowerPC)
CFLAGS  += $(ARCH) -std=gnu99 -fcommon -fno-strict-aliasing -fno-builtin-fprintf -include compat/printf_check.h -fsigned-char -Icompat -Wall -Wextra -Wno-unused-parameter -Wno-format-zero-length \
           -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-label -Wno-pointer-sign
# Debian's libc6-dev-i386 puts the 32-bit glibc headers under the x86_64 multiarch dir
ifeq ($(ARCH),-m32)
ISYSTEM := $(if $(wildcard /usr/include/i386-linux-gnu/bits),,-isystem /usr/include/x86_64-linux-gnu)
CFLAGS  += $(ISYSTEM)
endif
# the tree builds warning-free with gcc 14; WERROR= for other compilers
WERROR  ?= -Werror
CFLAGS  += $(WERROR)
LDFLAGS += $(ARCH) $(EXTRA_LDFLAGS)
CFLAGS  += $(EXTRA_CFLAGS)   # e.g. EXTRA_CFLAGS=-fsanitize=address EXTRA_LDFLAGS=-fsanitize=address
# l2passwd needs crypt(). Without the 32-bit libcrypt dev package (libcrypt-dev:i386)
# there is no libcrypt.so to find, so link the runtime library directly.
CRYPT   := $(if $(and $(filter -m32,$(ARCH)),$(wildcard /usr/lib/i386-linux-gnu/libcrypt.so.1)),\
             $(if $(wildcard /usr/lib/i386-linux-gnu/libcrypt.so),-lcrypt,/usr/lib/i386-linux-gnu/libcrypt.so.1),-lcrypt)
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
	sys_ctrl/common/sys/PPP.c \
	sys_ctrl/common/sys/brick_types.c \
	sys_ctrl/common/sys/ipmi.c \
	sys_ctrl/l3/IRouter/IRouterL3.c \
	sys_ctrl/l3/IRouter/IRouterOS.c \
	sys_ctrl/l3/api/L1Direct.c \
	sys_ctrl/l3/api/SCapi.c \
	sys_ctrl/l3/api/SCapiL2.c \
	sys_ctrl/l3/main/nvram.c \
	sys_ctrl/l3/sys/syslogLib.c

L2_SRCS := \
	sys_ctrl/l3/l2/l2.c \
	sys_ctrl/l3/l2/l1.c \
	sys_ctrl/l3/l2/l1net.c \
	sys_ctrl/l3/l2/l1sim.c \
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
	sys_ctrl/l3/l2/pty.c \
	sys_ctrl/l3/l2/route.c \
	sys_ctrl/common/main/EnetServer.c \
	sys_ctrl/common/Router/RouterSv.c \
	sys_ctrl/common/sys/Cmd.c \
	sys_ctrl/common/sys/minfo.c

L2TERM_SRCS := \
	sys_ctrl/l3/utils/l2term.c \
	sys_ctrl/l3/main/SysCfg.c \
	sys_ctrl/l3/api/SCapiConn.c

L2CMD_SRCS := \
	sys_ctrl/l3/utils/l2cmd.c

L2PASSWD_SRCS := \
	sys_ctrl/l3/utils/l2passwd.c

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

# Files done in the rewrite (CLEANUP.md phase 2) build with the warnings the
# decompiler residue elsewhere still needs switched off.
CLEAN_SRCS := \
	sys_ctrl/common/Router/Buff.c \
	sys_ctrl/common/Router/Event.c \
	sys_ctrl/common/Router/SocketIO.c \
	sys_ctrl/common/Router/Socket.c \
	sys_ctrl/common/Router/Router.c \
	sys_ctrl/common/Router/RouterCl.c \
	sys_ctrl/common/Router/RouterSv.c \
	sys_ctrl/common/IRouter/IRouter.c \
	sys_ctrl/common/IRouter/IRouter2Router.c \
	sys_ctrl/common/sys/Logger.c \
	sys_ctrl/common/sys/BuffWrite.c \
	sys_ctrl/common/sys/MemUsage.c \
	sys_ctrl/common/sys/ipmi.c \
	sys_ctrl/common/sys/l3paths.c \
	sys_ctrl/common/sys/Cmd.c \
	sys_ctrl/common/sys/PPP.c \
	sys_ctrl/common/sys/brick_types.c \
	sys_ctrl/common/sys/minfo.c \
	sys_ctrl/l3/main/nvram.c \
	sys_ctrl/l3/main/SysCfg.c \
	sys_ctrl/l3/api/SCapiConn.c \
	sys_ctrl/l3/api/SCapiL2.c \
	sys_ctrl/l3/api/SCapi.c \
	sys_ctrl/l3/api/L1Direct.c \
	sys_ctrl/l3/IRouter/IRouterOS.c \
	sys_ctrl/l3/sys/syslogLib.c \
	sys_ctrl/l3/IRouter/IRouterL3.c \
	sys_ctrl/common/main/EnetServer.c \
	sys_ctrl/common/main/L2Cfg.c \
	sys_ctrl/l3/l2/dmp.c \
	sys_ctrl/l3/l2/pty.c \
	sys_ctrl/l3/l2/serial.c \
	sys_ctrl/l3/l2/enet.c
$(CLEAN_SRCS:%.c=$(B)/%.o): CFLAGS += -Wunused-variable -Wunused-but-set-variable \
	-Wunused-label -Wpointer-sign

LIB_OBJS := $(LIB_SRCS:%.c=$(B)/%.o)
TOOLS    := l2 l2term l2cmd l2passwd
ifneq ($(WITH_L2GUI),)
TOOLS    += l2gui
else ifeq ($(QEMU),)
$(info l2gui skipped: no $(FLTK_CONFIG) (run ../retools/setup_fltk.sh $(FLTK_BITS)))
endif

.PHONY: all test check check-all difftest clean
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

$(B)/libsgi.a: $(LIB_OBJS)
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

$(B)/bin/l2passwd: $(L2PASSWD_SRCS:%.c=$(B)/%.o) $(B)/libsgi.a
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) $(CRYPT) -o $@

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

test:
	$(CC) $(CFLAGS) -fsyntax-only tests/layout_check.c
	@echo "layout check passed"

# make check: every differential test against this build (B=; cross builds run
# through their qemu wrappers). make check-all: the 32-bit, 64-bit and ASan
# builds, and s390x when ../retools/setup_s390x.sh has been run.
CHECK_BIN = $(abspath $(B))/$(if $(QEMU),qemu-bin,bin)
check: all
	$(if $(QEMU),,for t in tests/unit/*_test.sh; do $$t || exit 1; done)
	NEW_BIN=$(CHECK_BIN) tests/difftest.sh
	NEW_BIN=$(CHECK_BIN) tests/l2term_test.py
	NEW_BIN=$(CHECK_BIN) tests/smp_test.py
	NEW_BIN=$(CHECK_BIN) tests/nvram_test.py
	NEW_BIN=$(CHECK_BIN) tests/l1net_test.py
	NEW_BIN=$(CHECK_BIN) tests/l1_test.py
	NEW_BIN=$(CHECK_BIN) tests/options_test.sh
	NEW_BIN=$(CHECK_BIN) tests/l1direct_test.py
	$(if $(filter l2gui,$(TOOLS)),NEW_BIN=$(CHECK_BIN) tests/l2gui_test.py)

difftest: check

S390X := $(abspath ../tools/s390x/root/usr)
check-all:
	$(MAKE) check
	$(MAKE) check ARCH=-m64 B=build64
	ASAN_OPTIONS=detect_leaks=0 $(MAKE) check ARCH=-m64 B=build64asan \
	    EXTRA_CFLAGS=-fsanitize=address EXTRA_LDFLAGS=-fsanitize=address
	$(if $(wildcard $(S390X)/bin/qemu-s390x),PATH=$(S390X)/bin:$$PATH \
	    LD_LIBRARY_PATH=$(S390X)/lib/x86_64-linux-gnu $(MAKE) check \
	    CC=s390x-linux-gnu-gcc-14 AR=s390x-linux-gnu-ar ARCH= B=builds390x \
	    QEMU="$(S390X)/bin/qemu-s390x -L $(S390X)/s390x-linux-gnu")

clean:
	rm -rf $(B)
