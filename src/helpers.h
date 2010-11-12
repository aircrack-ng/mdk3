#ifndef HAVE_HELPERS_H
#define HAVE_HELPERS_H

char generate_channel();

char *generate_ssid();

int pps2usec(int pps);

// Call this again to read line after line
// At end of file, it returns NULL
// Start from the beginning by setting reset true
char *read_next_line(char *filename, char reset);

#endif