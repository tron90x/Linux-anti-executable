# Linux Anti-Executable Daemon Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -D_GNU_SOURCE
LDFLAGS = -lsqlite3 -lssl -lcrypto

TARGET = lexec-daemon
SRCS = main.c fanotify_handler.c whitelist.c ../common/hash.c
OBJS = $(SRCS:.c=.o)

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/sbin

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)/var/lib/lexec
	install -d $(DESTDIR)/var/run/lexec
	install -d $(DESTDIR)/etc/lexec

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
