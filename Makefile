# Reconstructed SGI L3 system-controller tools.
#
#   make            build everything into build/ (32-bit, matching the original ABI)
#   make test       layout checks: every SGI struct must match the original binaries
#   make difftest   l2 commands through original/rebuilt l2 + l2cmd, and l2term sessions;
#                   every output must match the original binaries'
#   make clean
#
# ARCH=-m32 keeps struct layouts identical to the originals (checked by make test).

CC      ?= gcc
ARCH    ?= -m32
CFLAGS  ?= -g -O0
CFLAGS  += $(ARCH) -std=gnu99 -fcommon -fno-strict-aliasing -fno-builtin -Icompat -Wall \
           -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-label -Wno-pointer-sign
# gcc 14 made these errors; the bootstrapped code still trips them (fix, then delete this line)
CFLAGS  += -Wno-error=int-conversion \
           -Wno-error=incompatible-pointer-types -Wno-error=return-mismatch
# Debian's libc6-dev-i386 puts the 32-bit glibc headers under the x86_64 multiarch dir
ifeq ($(ARCH),-m32)
CFLAGS  += $(if $(wildcard /usr/include/i386-linux-gnu/bits),,-isystem /usr/include/x86_64-linux-gnu)
endif
LDFLAGS += $(ARCH)
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

LIB_OBJS := $(LIB_SRCS:%.c=$(B)/%.o)
TOOLS    := l2 l2term l2cmd l2passwd

.PHONY: all test difftest clean
all: $(TOOLS:%=$(B)/bin/%)

$(B)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

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

test:
	$(CC) $(CFLAGS) -fsyntax-only tests/layout_check.c
	@echo "layout check passed"

difftest: all
	tests/difftest.sh
	tests/l2term_test.py

clean:
	rm -rf $(B)
