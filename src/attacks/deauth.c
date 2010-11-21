#include <stdio.h>
#include <unistd.h>

#include "deauth.h"
#include "../osdep.h"

#define DEAUTH_MODE 'd'
#define DEAUTH_NAME "Deauthentication and Disassociation"

struct deauth_options {
  char *greylist;
  unsigned char isblacklist;
  unsigned int speed;
};

//Global things, shared by packet creation and stats printing
struct ether_addr bssid, station;

void deauth_shorthelp()
{
  printf("  Sends deauthentication and disassociation packets to stations\n");
  printf("  based on data traffic to disconnect all clients from an AP.\n");
}

void deauth_longhelp()
{
  printf( "  Sends deauthentication and disassociation packets to stations\n"
	  "  based on data traffic to disconnect all clients from an AP.\n"
	  "      -w <filename>\n"
	  "         Read file containing MACs not to care about (Whitelist mode)\n"
	  "      -b <filename>\n"
	  "         Read file containing MACs to run test on (Blacklist Mode)\n"
	  "      -s <pps>\n"
	  "         Set speed in packets per second (Default: unlimited)\n"
	  "      -c [chan,chan,chan,...]\n"
	  "         Enable channel hopping. Without providing any channels, mdk3 will hop an all\n"
	  "         14 b/g channels. Channel will be changed every 3 seconds.\n");
}

void *deauth_parse(int argc, char *argv[]) {
  int opt, ch;
  unsigned int i;
  struct deauth_options *dopt = malloc(sizeof(struct deauth_options));
  
  dopt->greylist = NULL;
  dopt->isblacklist = 0;
  dopt->speed = 0;

  while ((opt = getopt(argc, argv, "w:b:s:c:")) != -1) {
    switch (opt) {
      case 'w':
	if (dopt->isblacklist || dopt->greylist) {
	  printf("Only one -w or -b may be selected once\n"); return NULL; }
	dopt->greylist = malloc(strlen(optarg) + 1); strcpy(dopt->greylist, optarg);
      break;
      case 'b':
	if (dopt->isblacklist || dopt->greylist) {
	  printf("Only one -w or -b may be selected once\n"); return NULL; }
	dopt->greylist = malloc(strlen(optarg) + 1); strcpy(dopt->greylist, optarg);
	dopt->isblacklist = 1;
      break;
      case 's':
	dopt->speed = (unsigned int) atoi(optarg);
      break;
      case 'c':
	init_channel_hopper(optarg, 3000000);
      break;
      default:
	deauth_longhelp();
	printf("\n\nUnknown option %c\n", opt);
	return NULL;
    }
  }
  
  return (void *) dopt;
}


struct packet deauth_getpacket(void *options) {
  struct deauth_options *bopt = (struct deauth_options *) options;
  struct packet pkt;

}

void deauth_print_stats(void *options) {
  options = options; //Avoid unused warning
  printf("\rCurrent MAC: "); print_mac(bssid);
}

void deauth_perform_check(void *options) {
  //Nothing to check for beacon flooding attacks
  options = options; //Avoid unused warning
}

struct attacks load_deauth() {
  struct attacks this_attack;
  char *deauth_name = malloc(strlen(DEAUTH_NAME) + 1);
  strcpy(deauth_name, DEAUTH_NAME);

  this_attack.print_shorthelp = (fp) deauth_shorthelp;
  this_attack.print_longhelp = (fp) deauth_longhelp;
  this_attack.parse_options = (fpo) deauth_parse;
  this_attack.get_packet = (fpp) deauth_getpacket;
  this_attack.print_stats = (fps) deauth_print_stats;
  this_attack.perform_check = (fps) deauth_perform_check;
  this_attack.mode_identifier = DEAUTH_MODE;
  this_attack.attack_name = deauth_name;

  return this_attack;
}