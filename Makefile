#########################
# Makefile for keypress #
#########################

BIN ?= keypress

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
MANDIR ?= $(DATADIR)/man

INSTALL ?= install
RM ?= rm

SRC = src/*.c

CFLAGS ?= -O3 -fstack-protector-strong
CFLAGS += -Wall -Wextra -pedantic

LIBS ?= -lncurses

$(BIN): $(SRC)
	$(CC) -o $(BIN) $(SRC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(LIBS)

build: $(BIN)

clean:
	$(RM) -- $(BIN)

install: $(BIN)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(BIN) $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0644 $(BIN).1 $(DESTDIR)$(MANDIR)/man1
	@printf "Successfully installed $(BIN)\n"

uninstall:
	$(RM) -- $(DESTDIR)$(BINDIR)/$(BIN)
	$(RM) -- $(DESTDIR)$(MANDIR)/man1/$(BIN).1*
	@printf "Successfully uninstalled $(BIN)\n"
