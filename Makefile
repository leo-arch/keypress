#########################
# Makefile for keypress #
#########################

BIN ?= keypress

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share

INSTALL ?= install
RM ?= rm

SRC = $(BIN).c

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
	@printf "Successfully installed $(BIN)\n"

uninstall:
	$(RM) -- $(DESTDIR)$(BINDIR)/$(BIN)
	@printf "Successfully uninstalled $(BIN)\n"
