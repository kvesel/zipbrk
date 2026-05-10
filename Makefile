CC      = gcc
CFLAGS  = -Wall -Wextra -O2
PREFIX  = /usr
BINDIR  = $(PREFIX)/bin
MANDIR  = $(PREFIX)/share/man/man1

all: zipbrk

zipbrk: zipbrk.c
	$(CC) $(CFLAGS) -o $@ $<

install: zipbrk
	install -Dm755 zipbrk   $(DESTDIR)$(BINDIR)/zipbrk
	install -Dm644 zipbrk.1 $(DESTDIR)$(MANDIR)/zipbrk.1

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/zipbrk
	rm -f $(DESTDIR)$(MANDIR)/zipbrk.1

clean:
	rm -f zipbrk

.PHONY: all install uninstall clean
