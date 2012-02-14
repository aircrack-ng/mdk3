#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "wids.h"
#include "../osdep.h"
#include "../helpers.h"
#include "../channelhopper.h"

#define WIDS_MODE 'w'
#define WIDS_NAME "WIDS Confusion"

struct wids_options {
  char *target;
  int zerochaos;
  int speed;
  int aps;
  int clients;
  int auths;
  int deauths;
};

//Global things, shared by packet creation and stats printing
struct ether_addr target_client, target_ap;

void wids_shorthelp()
{
  printf("  Confuse/Abuse Intrusion Detection and Prevention Systems by\n");
  printf("  cross-connecting clients to multiple WDS nodes or fake rogue APs.\n");
}

void wids_longhelp()
{
  printf( "  Confuse/Abuse Intrusion Detection and Prevention Systems by\n"
	  "  cross-connecting clients to multiple WDS nodes or fake rogue APs.\n"
	  "  Confuses a WDS with multi-authenticated clients which messes up routing tables\n"
	  "      -e <SSID>\n"
	  "         SSID of target WDS network\n"
	  "      -c [chan,chan,...,chan[:speed]]\n"
	  "         Enable channel hopping. When -c h is given, mdk3 will hop an all\n"
	  "         14 b/g channels. Channel will be changed every 3 seconds,\n"
	  "         if speed is not specified. Speed value is in milliseconds!\n"
	  "      -z\n"
	  "         activate Zero_Chaos' WIDS exploit\n"
	  "         (authenticates clients from a WDS to foreign APs to make WIDS go nuts)\n"
	  "      -s <pps>\n"
	  "         Set speed in packets per second (Default: 100)\n");
}

void *wids_parse(int argc, char *argv[]) {
  int opt, speed;
  char *speedstr;
  struct wids_options *wopt = malloc(sizeof(struct wids_options));

  wopt->target = NULL;
  wopt->zerochaos = 0;
  wopt->speed = 100;
  wopt->aps = wopt->clients = wopt->auths = wopt->deauths = 0;

  while ((opt = getopt(argc, argv, "e:c:zs:")) != -1) {
    switch (opt) {
      case 'e':
	if (strlen(optarg) > 255) {
	  printf("ERROR: SSID too long\n"); return NULL;
	} else if (strlen(optarg) > 32) {
	  printf("NOTE: Using Non-Standard SSID with length > 32\n");
	}
	wopt->target = malloc(strlen(optarg) + 1); strcpy(wopt->target, optarg);
      break;
      case 'c':
  	speed = 3000000;
  	speedstr = strrchr(optarg, ':');
  	if (speedstr != NULL) {
  	  speed = 1000 * atoi(speedstr + 1);
  	}
  	if (optarg[0] == 'h') {
  	  init_channel_hopper(NULL, speed);
  	} else {
  	  init_channel_hopper(optarg, speed);
  	}
      break;
      case 'z':
        wopt->zerochaos = 1;
      break;
      case 's':
        wopt->speed = (unsigned int) atoi(optarg);
      break;
      default:
	wids_longhelp();
	printf("\n\nUnknown option %c\n", opt);
	return NULL;
    }
  }

  return (void *) wopt;
}


struct packet wids_getpacket(void *options) {
  struct wids_options *wopt = (struct wids_options *) options;
  struct packet pkt;



  sleep_till_next_packet(wopt->speed);
  return pkt;
}

void wids_print_stats(void *options) {
  struct wids_options *wopt = (struct wids_options *) options;

  printf("\rAPs found: %d   Clients found: %d   Completed Auth-Cycles: %d   Caught Deauths: %d\n", wopt->aps, wopt->clients, wopt->auths, wopt->deauths);
}

void wids_perform_check(void *options) {
  //Nothing to check
  options = options; //Avoid unused warning
}

struct attacks load_wids() {
  struct attacks this_attack;
  char *wids_name = malloc(strlen(WIDS_NAME) + 1);
  strcpy(wids_name, WIDS_NAME);

  this_attack.print_shorthelp = (fp) wids_shorthelp;
  this_attack.print_longhelp = (fp) wids_longhelp;
  this_attack.parse_options = (fpo) wids_parse;
  this_attack.get_packet = (fpp) wids_getpacket;
  this_attack.print_stats = (fps) wids_print_stats;
  this_attack.perform_check = (fps) wids_perform_check;
  this_attack.mode_identifier = WIDS_MODE;
  this_attack.attack_name = wids_name;

  return this_attack;
}
