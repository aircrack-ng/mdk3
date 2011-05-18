#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "osdep/osdep.h"
#include "osdep.h"

static struct wif *_wi_in, *_wi_out;

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;
} dev;

int current_channel = 0;


int osdep_start(char *interface)
{
    /* open the replay interface */
    _wi_out = wi_open(interface);
    if (!_wi_out)
    	return 1;
    dev.fd_out = wi_fd(_wi_out);

    /* open the packet source */
    _wi_in = _wi_out;
    dev.fd_in = dev.fd_out;

    /* XXX */
    dev.arptype_in = dev.arptype_out;
    
    return 0;
}


int osdep_send_packet(struct packet *pkt)
{
	struct wif *wi = _wi_out; /* XXX globals suck */
	if (wi_write(wi, pkt->data, pkt->len, NULL) == -1) {
		switch (errno) {
		case EAGAIN:
		case ENOBUFS:
			usleep(10000);
			return 0; /* XXX not sure I like this... -sorbo */
		}

		perror("wi_write()");
		return -1;
	}

	return 0;
}


struct packet osdep_read_packet()
{
	struct wif *wi = _wi_in; /* XXX */
	int rc;
	struct packet pkt;
	
	pkt.data = malloc(MAX_PACKET_SIZE);
	
	do {
	  rc = wi_read(wi, pkt.data, MAX_PACKET_SIZE, NULL);
	  if (rc == -1) {
	    perror("wi_read()");
	    free(pkt.data);
	    pkt.len = 0;
	    return pkt;
	  }
	} while (rc < 1);

	pkt.len = rc;
	pkt.data = realloc(pkt.data, pkt.len);
	return pkt;
}


void osdep_set_channel(int channel)
{
    wi_set_channel(_wi_out, channel);
    current_channel = channel;
}


int osdep_get_channel()
{
    return current_channel;
}


void osdep_set_rate(int rate)
{
    int i, valid = 0;
    
    for (i=0; i<VALID_RATE_COUNT; i++) {
      if (VALID_BITRATES[i] == rate) valid = 1;
    }
    
    if (!valid) printf("BUG: osdep_set_rate(): Invalid bitrate selected!\n");
    
    wi_set_rate(_wi_out, rate);
}