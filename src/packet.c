#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>

#include "packet.h"

void create_ieee_hdr(struct packet *pkt, uint8_t type, char dsflags, uint16_t duration, struct ether_addr destination, struct ether_addr source, struct ether_addr bssid_or_transm, struct ether_addr recv, uint8_t fragment) {
  static uint16_t seqno = 0;
  struct ieee_hdr *hdr = (struct ieee_hdr *) pkt->data;

  //If fragment, do not increase sequence
  if (!fragment) seqno++; seqno %= 0x1000;
  
  if (fragment > 0x0F) {
    printf("WARNING: Fragment number exceeded maximum of 15, resetting to 0.\n");
    fragment = 0;
  }
  
  hdr->type = type;
  
  hdr->flags = 0x00;
  //if (wep) hdr->flags |= 0x40; //If somebody needs WEP, here it is :D
  
  switch (dsflags) {
    case 'a':	//Ad Hoc, Beacons:    ToDS 0 FromDS 0  Addr: DST, SRC, BSS
      MAC_COPY(hdr->addr1, destination);
      MAC_COPY(hdr->addr2, source);
      MAC_COPY(hdr->addr3, bssid_or_transm);
      break;
    case 'f':	//From AP to station: ToDS 0 FromDS 1  Addr: DST, BSS, SRC
      hdr->flags |= 0x02;
      MAC_COPY(hdr->addr1, destination);
      MAC_COPY(hdr->addr2, bssid_or_transm);
      MAC_COPY(hdr->addr3, source);
      break;
    case 't':	//From station to AP: ToDS 1 FromDS 1  Addr: BSS, SRC, DST
      hdr->flags |= 0x01;
      MAC_COPY(hdr->addr1, bssid_or_transm);
      MAC_COPY(hdr->addr2, source);
      MAC_COPY(hdr->addr3, destination);
      break;
    case 'w':	//WDS:                ToDS 1 FromDS 1  Addr: RCV, TRN, DST ... SRC
      hdr->flags |= 0x03;
      MAC_COPY(hdr->addr1, recv);
      MAC_COPY(hdr->addr2, bssid_or_transm);
      MAC_COPY(hdr->addr3, destination);
      memcpy((pkt->data) + (sizeof(struct ieee_hdr)), source.ether_addr_octet, ETHER_ADDR_LEN);
      break;
    default:
      printf("ERROR: DS Flags invalid, use only a, f, t or w! Frame will have no MAC adresses!\n");
  }
  
  hdr->duration = htole16(duration);
  
  hdr->frag_seq = htole16(fragment | (seqno << 4));
  
  //TODO: Maybe we need to add support for other frame types beside DATA and Beacon.
  //      A good idea would also be QoS Data support
  
  pkt->len = sizeof(struct ieee_hdr);
  if ((hdr->flags & 0x03) == 0x03) pkt->len += 6;	//Extra MAC in WDS packets
}


struct ether_addr *get_addr(struct packet *pkt, char type) {
  uint8_t dsflags;
  struct ieee_hdr *hdr;
  struct ether_addr *src, *dst, *bss, *trn = NULL;
  
  if(! pkt) {
    printf("BUG: Got NULL packet!\n");
    return NULL;
  }
  
  hdr = (struct ieee_hdr *) pkt->data;
  dsflags = hdr->flags & 0x03;
  
  switch (dsflags) {
    case 0x00:
      dst = &(hdr->addr1);
      src = &(hdr->addr2);
      bss = &(hdr->addr3);
      break;
    case 0x01:
      bss = &(hdr->addr1);
      src = &(hdr->addr2);
      dst = &(hdr->addr3);
      break;
    case 0x02:
      dst = &(hdr->addr1);
      bss = &(hdr->addr2);
      src = &(hdr->addr3);
      break;
    case 0x03:
      bss = &(hdr->addr1);
      trn = &(hdr->addr2);
      dst = &(hdr->addr3);
      src = (struct ether_addr *) &(pkt->data) + (sizeof(struct ieee_hdr));
      break;
  }
  
  switch (type) {
    case 'b':
      return bss;
    case 'd':
      return dst;
    case 's':
      return src;
    case 't':
      return trn;
  }
  
  return NULL;
}

struct ether_addr *get_bssid(struct packet *pkt) {
  return get_addr(pkt, 'b');
}

struct ether_addr *get_source(struct packet *pkt) {
  return get_addr(pkt, 's');
}

struct ether_addr *get_destination(struct packet *pkt) {
  return get_addr(pkt, 'd');
}

struct ether_addr *get_transmitter(struct packet *pkt) {
  return get_addr(pkt, 't');
}

struct ether_addr *get_receiver(struct packet *pkt) {
  return get_addr(pkt, 'b');
}

struct packet create_beacon(struct ether_addr bssid, char *ssid, uint8_t channel, char encryption, unsigned char bitrate, char adhoc) {
  struct packet beacon;
  struct beacon_fixed *bf;
  static uint64_t internal_timestamp = 0;
  struct ether_addr bc;
  
  beacon.data = malloc(2048);	//Will resize it later
  
  MAC_SET_BCAST(bc);
  create_ieee_hdr(&beacon, IEEE80211_TYPE_BEACON, 'a', 0, bc, bssid, bssid, bc, 0);

  bf = (struct beacon_fixed *) (beacon.data + beacon.len);
  
  internal_timestamp += 0x400 * DEFAULT_BEACON_INTERVAL;
  bf->timestamp = htole64(internal_timestamp);
  bf->interval = htole16(DEFAULT_BEACON_INTERVAL);
  bf->capabilities = 0x0000;
  if (adhoc) { bf->capabilities |= 0x0002; } else { bf->capabilities |= 0x0001; }
  if (encryption != 'n') bf->capabilities |= 0x0010;

  beacon.len += sizeof(struct beacon_fixed);
  beacon.data[beacon.len] = 0x00;	//SSID parameter set
  beacon.data[beacon.len+1] = (uint8_t) strlen(ssid);	//SSID len
  memcpy(beacon.data + beacon.len + 2, ssid, strlen(ssid));	//Copy the SSID
  
  beacon.len += strlen(ssid) + 2;
  memcpy(beacon.data + beacon.len, DEFAULT_11B_RATES, 6);	//11 MBit
  
  beacon.len += 6;
  beacon.data[beacon.len] = 0x03;	//Channel set
  beacon.data[beacon.len+1] = 0x01;	//One channel
  beacon.data[beacon.len+2] = channel;
  
  beacon.len += 3;
  if (bitrate == 54) {
    memcpy(beacon.data + beacon.len, DEFAULT_11G_RATES, 10);	//54 MBit
    beacon.len += 10;
  }
  
  if (encryption == 't') {
    memcpy(beacon.data + beacon.len, DEFAULT_WPA_TKIP_TAG, 26);
    beacon.len += 26;
  }
  if (encryption == 'a') {
    memcpy(beacon.data + beacon.len, DEFAULT_WPA_AES_TAG, 26);
    beacon.len += 26;
  }
  
  beacon.data = realloc(beacon.data, beacon.len);
  return beacon;
}

struct packet create_auth(struct ether_addr bssid, struct ether_addr client, uint16_t seq) {
  struct packet auth;
  struct auth_fixed *af;
  
  auth.data = malloc(30);
  
  create_ieee_hdr(&auth, IEEE80211_TYPE_AUTH, 'a', 314, bssid, client, bssid, bssid, 0);
  
  af = (struct auth_fixed *) (auth.data + auth.len);
  
  af->algorithm = AUTH_ALGORITHM_OPEN;
  af->seq = seq;
  af->status = AUTH_STATUS_SUCCESS;
  
  auth.len = 30;
  return auth;
}