#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "probing.h"

#define PROBING_MODE 'p'
#define PROBING_NAME "SSID Probing and Bruteforcing"

struct probing_options {
  struct ether_addr *target;
  char *filename;
  char *ssid;
  unsigned int speed;
  char *charsets;
  char *proceed;
  unsigned char renderman;
};

//Global things, shared by packet creation and stats printing


void probing_shorthelp()
{
  printf("  Probes APs and checks for answer, useful for checking if SSID has\n");
  printf("  been correctly decloaked and if AP is in your sending range.\n");
  printf("  Bruteforcing of hidden SSIDs with or without a wordlist is also available.\n");
}


void probing_longhelp()
{
  printf( "  Probes APs and checks for answer, useful for checking if SSID has\n"
	  "  been correctly decloaked and if AP is in your sending range.\n"
	  "  Bruteforcing of hidden SSIDs with or without a wordlist is also available.\n"
	  "      -e <ssid>\n"
	  "         SSID to probe for\n"
	  "      -f <filename>\n"
	  "         Read SSIDs from file for bruteforcing hidden SSIDs\n"
	  "      -t <bssid>\n"
	  "         Set MAC address of target AP\n"
	  "      -s <pps>\n"
	  "         Set speed (Default: 400)\n"
	  "      -b <character sets>\n"
	  "         Use full Bruteforce mode (recommended for short SSIDs only!)\n"
	  "         You can select multiple character sets at once:\n"
	  "         * n (Numbers:   0-9)\n"
	  "         * u (Uppercase: A-Z)\n"
	  "         * l (Lowercase: a-z)\n"
	  "         * s (Symbols: ASCII)\n"
	  "      -p <word>\n"
	  "         Continue bruteforcing, starting at <word>.\n"
	  "      -r\n"
	  "         Activates RenderMan's discovery tool to politely scan hidden\n"
	  "         networks for a list of known SSIDs\n");
}


void *probing_parse(int argc, char *argv[]) {
  int opt;
  struct probing_options *popt = malloc(sizeof(struct probing_options));

  popt->target = NULL;
  popt->filename = NULL;
  popt->ssid = NULL;
  popt->speed = 400;
  popt->charsets = NULL;
  popt->proceed = NULL;
  popt->renderman = 0;
  
  while ((opt = getopt(argc, argv, "e:f:t:s:b:p:r")) != -1) {
    switch (opt) {
      case 'e':
	if (popt->renderman || popt->filename || popt->charsets || popt->proceed) { 
	  printf("Select only one mode please (either -e, -f, -b or -r), not two of them!\n"); return NULL; }
	popt->ssid = malloc(strlen(optarg) + 1);
	strcpy(popt->ssid, optarg);
      break;
      case 'f':
	if (popt->renderman || popt->ssid || popt->charsets || popt->proceed) { 
	  printf("Select only one mode please (either -e, -f, -b or -r), not two of them!\n"); return NULL; }
	popt->filename = malloc(strlen(optarg) + 1);
	strcpy(popt->filename, optarg);
      break;
      case 's':
	popt->speed = (unsigned int) atoi(optarg);
      break;
      case 't':
	if (popt->renderman || popt->ssid) { 
	  printf("Targets (-t) are not needed for this Probing mode\n"); return NULL; }
	popt->target = malloc(sizeof(struct ether_addr));
	*(popt->target) = parse_mac(optarg);
      break;
      case 'b':
	if (popt->renderman || popt->filename || popt->ssid) { 
	  printf("Select only one mode please (either -e, -f, -b or -r), not two of them!\n"); return NULL; }
	popt->charsets = malloc(strlen(optarg) + 1);
	strcpy(popt->charsets, optarg);
      case 'p':
	if (popt->renderman || popt->ssid || popt->filename) { 
	  printf("Select only one mode please (either -e, -f, -b or -r), not two of them!\n"); return NULL; }
	popt->proceed = malloc(strlen(optarg) + 1);
	strcpy(popt->proceed, optarg);
      break;
      case 'r':
	if (popt->filename || popt->ssid || popt->charsets || popt->proceed) { 
	  printf("Select only one mode please (either -e, -f, -b or -r), not two of them!\n"); return NULL; }
	popt->renderman = 1;
      break;
      default:
	probing_longhelp();
	printf("\n\nUnknown option %c\n", opt);
	return NULL;
    }
  }
  
  if ((! popt->target) && (popt->filename || popt->charsets)) {
    printf("Bruteforce modes need a target MAC address (-t)\n");
    return NULL;
  }
  
  if ((! popt->charsets) && popt->proceed) {
    printf("You need to specify a character set (-b)\n");
    return NULL;
  }
  
  return (void *) popt;
}


struct packet probing_getpacket(void *options) {

}


void probing_print_stats(void *options) {
  struct probing_options *popt = (struct probing_options *) options;
  

}



void probing_perform_check(void *options) {
  //unused
  options = options; //prevent warning
}

struct attacks load_probing() {
  struct attacks this_attack;
  char *probing_name = malloc(strlen(PROBING_NAME) + 1);
  strcpy(probing_name, PROBING_NAME);

  this_attack.print_shorthelp = (fp) probing_shorthelp;
  this_attack.print_longhelp = (fp) probing_longhelp;
  this_attack.parse_options = (fpo) probing_parse;
  this_attack.get_packet = (fpp) probing_getpacket;
  this_attack.print_stats = (fps) probing_print_stats;
  this_attack.perform_check = (fps) probing_perform_check;
  this_attack.mode_identifier = PROBING_MODE;
  this_attack.attack_name = probing_name;

  return this_attack;
}
