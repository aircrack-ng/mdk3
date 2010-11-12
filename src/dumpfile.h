#ifndef HAVE_DUMPFILE_H
#define HAVE_DUMPFILE_H

void dump_packet(unsigned char *data, unsigned int len);

void start_dump(char *filename);

void stop_dump();

#endif
