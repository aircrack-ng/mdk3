#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "helpers.h"

char generate_channel()
{
// Generate a random channel

    char c = 0;
    c = (random() % 14) + 1;
    return c;
}


char generate_printable_char()
{
// Generate random printable ascii char

    char rnd = 0;
    rnd = (random() % 94) + ' ';

    return rnd;
}


char *generate_ssid()
{
// Generate random VALID SSID
// Need another to generate INVALID SSIDs (overlenght) for testing their impact on wireless devices

    char *ssid = (char*) malloc(33);
    int len=0;
    int t;

    len = (random() % 32) + 1;

    for (t=0; t<len; t++) ssid[t] = generate_printable_char();
    ssid[len]='\x00';

    return ssid;
}


int pps2usec(int pps)
{
// Very basic routine to convert desired packet rate to µs
// µs values were measured with rt2570 device
// Should use /dev/rtc like in aireplay

    int usec;
    int ppc = 1000000;

    if (pps>15) ppc=950000;
    if (pps>35) ppc=800000;
    if (pps>75) ppc=730000;
    if (pps>125)ppc=714000;

    usec = ppc / pps;

    return usec;
}

char *read_next_line(char *filename, char reset)
{
    static int last_pos = 0;
    int bytesread;
    char *line = malloc(1);
    char **pline = &line;
    FILE *file_fp;
    size_t initsize = 1;
    
    if (reset) last_pos = 0;
    
    if ((file_fp = fopen(filename, "r")) == NULL) {
      printf("Cannot open file: %s\n", filename);
      exit(2);
    }
    
    fseek(file_fp, last_pos, SEEK_SET);
    bytesread = getline(pline, &initsize, file_fp);
    line = *pline;
    
    if (bytesread == -1) {
      last_pos = 0;
      fclose(file_fp);
      return NULL;
    }

    last_pos = ftell(file_fp);
    fclose(file_fp);
    
    //Remove newline if any
    if (line[strlen(line) - 1] == '\n') line[strlen(line) - 1] = 0x00;
    
    return line;
}
