PREFIX		= /usr/local
SBINDIR		= $(PREFIX)/sbin
MANDIR		= $(PREFIX)/share/man

SRC		= src
MDK3_SRC	= src/mdk3

all: $(MDK3_SRC)

$(MDK3_SRC):
	$(MAKE) -C $(SRC)

install: $(MDK3_SRC)
	PREFIX=$(PREFIX) $(MAKE) -C $(SRC) install
	install -D -m 0644 man/mdk3.8 $(MANDIR)/man8/mdk3.8
	gzip -f $(MANDIR)/man8/mdk3.8

clean:
	$(MAKE) -C $(SRC) clean

distclean: clean
