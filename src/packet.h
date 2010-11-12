#ifndef HAVE_PACKET_H
#define HAVE_PACKET_H

#include <inttypes.h>

#include "mac_addr.h"

#define IEEE80211_TYPE_BEACON	0x80
#define IEEE80211_TYPE_DATA	0x08
#define IEEE80211_TYPE_QOSDATA	0x88

#define DEFAULT_BEACON_INTERVAL	0x64
#define DEFAULT_11B_RATES	"\x01\x04\x82\x84\x8b\x96"
#define DEFAULT_11G_RATES	"\x32\x08\x0c\x12\x18\x24\x30\x48\x60\x6c"
#define DEFAULT_WPA_TKIP_TAG	"\xDD\x18\x00\x50\xF2\x01\x01\x00\x00\x50\xF2\x02\x01\x00\x00\x50\xF2\x02\x01\x00\x00\x50\xF2\x02\x00\x00"
#define DEFAULT_WPA_AES_TAG	"\xDD\x18\x00\x50\xF2\x01\x01\x00\x00\x50\xF2\x04\x01\x00\x00\x50\xF2\x04\x01\x00\x00\x50\xF2\x02\x00\x00"


struct packet {
  unsigned char *data;
  unsigned int len;
};

struct ieee_hdr {
  uint8_t type;
  uint8_t flags;
  uint16_t duration;
  struct ether_addr addr1;
  struct ether_addr addr2;
  struct ether_addr addr3;
  uint16_t frag_seq;
} __attribute__((packed));

struct beacon_fixed {
  uint64_t timestamp;
  uint16_t interval;
  uint16_t capabilities;
} __attribute__((packed));

//dsflags: 'a' = AdHoc, Beacon   'f' = From DS   't' = To DS   'w' = WDS (intra DS)
//Set recv to NULLMAC if you don't create WDS packets. (its ignored anyway)
void create_ieee_hdr(struct packet *pkt, uint8_t type, char dsflags, uint16_t duration, struct ether_addr destination, struct ether_addr source, struct ether_addr bssid_or_transm, struct ether_addr recv, uint8_t fragment);

struct ether_addr *get_bssid(struct packet *pkt);

struct ether_addr *get_source(struct packet *pkt);

struct ether_addr *get_destination(struct packet *pkt);

struct ether_addr *get_transmitter(struct packet *pkt);

struct ether_addr *get_receiver(struct packet *pkt);

//encryption: 'n' = None   'w' = WEP   't' = TKIP (WPA)   'a' = AES (WPA2)
//If bitrate is 54, you'll get an bg network, b only otherwise
struct packet create_beacon(struct ether_addr bssid, char *ssid, uint8_t channel, char encryption, unsigned char bitrate, char adhoc);

#endif