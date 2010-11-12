#ifndef HAVE_OSDEP_H
#define HAVE_OSDEP_H

int osdep_start(char *interface);

int osdep_send_packet(unsigned char *buf, size_t count);

int osdep_read_packet(unsigned char *buf, size_t count);

void osdep_set_channel(int channel);

int osdep_get_channel();

#endif
