# Makefile
# Purpose: Provides the base build scaffolding for the epoll-echo project.
# Uses conservative hardening-friendly defaults suitable for GNU/Linux.

CC       ?= cc
CFLAGS   ?= -O2 -g
CFLAGS   += -std=c11 -Wall -Wextra \
            -Werror=implicit-function-declaration \
            -Wpointer-arith -Wformat -Wshadow \
            -D_GNU_SOURCE -fstack-protector-strong -D_FORTIFY_SOURCE=2
CPPFLAGS += -Iinclude -MMD -MP
LDFLAGS  ?= -Wl,-z,relro -Wl,-z,now -pie
LDLIBS   ?=
ARTIFACT_PATTERNS := ../epoll-echo_*.deb ../epoll-echo_*.dsc ../epoll-echo_*.changes \
	../epoll-echo_*.buildinfo ../epoll-echo_*.tar.* ../epoll-echo-dbgsym_*.ddeb

ifeq ($(ENABLE_SYSTEMD),1)
CPPFLAGS += -DENABLE_SYSTEMD
LDLIBS   += -lsystemd
endif

BIN  := epoll-echo
SRCS := \
	src/main.c \
	src/loop.c \
	src/tcp.c \
	src/udp.c \
	src/cmd.c \
	src/stats.c \
	src/timeutil.c \
	src/log.c \
	src/net.c
OBJS := $(SRCS:.c=.o)
DEPS := $(OBJS:.o=.d)

.PHONY: all clean test deb

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJS) $(BIN) $(DEPS)

test: $(BIN)
	@echo "No automated tests are defined yet."

deb:
	dpkg-buildpackage -us -uc
	debian/rules clean
	@set -e; \
	for pattern in $(ARTIFACT_PATTERNS); do \
		for f in $$pattern; do \
			[ -e "$$f" ] || continue; \
			mv -f "$$f" .; \
		done; \
	done

-include $(DEPS)
