#ifndef HAVE_OSDEP_H
#define HAVE_OSDEP_H

#include "packet.h"

#define MAX_PACKET_SIZE 2048

int osdep_start(char *interface);

int osdep_send_packet(struct packet *pkt);

struct packet osdep_read_packet();

void osdep_set_channel(int channel);

int osdep_get_channel();

#endif
