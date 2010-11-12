CFLAGS		= -g -O3 -Wall -Wextra
LINKFLAGS	= -lpthread -lpcap

SBINDIR		= $(PREFIX)/sbin
MANDIR		= $(PREFIX)/share/man

OSD		= osdep
LIBS		= -L$(OSD) -l$(OSD)
LIBOSD		= $(OSD)/lib$(OSD).so

OBJS		= debug.o helpers.o mac_addr.o linkedlist.o greylist.o dumpfile.o packet.o
OBJS_OSD	= osdep.o channelhopper.o

ATTACKS		= attacks
OBJ_ATT		= attacks/*.o

all: osd mdk3 $(OBJ_ATT)

osd:
	$(MAKE) -C $(OSD)

$(LIBOSD):
	$(MAKE) -C $(OSD)

$(OBJ_ATT):
	$(MAKE) -C $(ATTACKS)

mdk3: mdk3.c $(OSD)/libosdep.a $(OBJS) $(OBJS_OSD) $(OBJ_ATT)
	$(CC) $(CFLAGS) $(^) -o $(@) $(LIBS) $(LINKFLAGS)

test: test.c $(OBJS)
	$(CC) $(CFLAGS) $(^) -o $(@) $(LINKFLAGS)

install: mdk3
	install -D -m 0755 $^ $(SBINDIR)/$^
	$(MAKE) -C $(ATTACKS) install
	$(MAKE) -C $(OSD) install

clean:
	rm -f mdk3
	rm -f $(OBJS) $(OBJS_OSD)
	$(MAKE) -C $(OSD) clean
	$(MAKE) -C $(ATTACKS) clean

distclean: clean
