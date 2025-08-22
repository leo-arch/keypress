BIN ?= keypress

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
MANDIR ?= $(DATADIR)/man

INSTALL ?= install
RM ?= rm

CFLAGS += -MD -O3 -std=c99 -fstack-protector-strong -Wall -Wextra -pedantic

OBJECTS=src/draw.o src/keypress.o src/options.o src/term.o src/translate_key.o
DEPS=$(OBJECTS:.o=.d)

$(BIN): $(OBJECTS)
	$(CC) $(CFLAGS) $(CCFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

build: $(BIN)

clean:
	$(RM) -- $(BIN)
	$(RM) -- $(DEPS)

install: $(BIN)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(BIN) $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0644 $(BIN).1 $(DESTDIR)$(MANDIR)/man1
	@printf "Successfully installed $(BIN)\n"

uninstall:
	$(RM) -- $(DESTDIR)$(BINDIR)/$(BIN)
	$(RM) -- $(DESTDIR)$(MANDIR)/man1/$(BIN).1*
	@printf "Successfully uninstalled $(BIN)\n"

-include $(DEPS)
