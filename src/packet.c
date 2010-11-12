#include <endian.h>

#include "packet.h"

void create_ieee_hdr(struct packet *pkt, uint8_t type, char dsflags, uint16_t duration, struct ether_addr destination, struct ether_addr source, struct ether_addr bssid_or_transm, struct ether_addr recv, uint8_t fragment) {
  static uint8_t seqno = 0;
  struct ieee_hdr *hdr = (struct ieee_hdr *) pkt->data;

  //If fragment, do not increase sequence
  if (!fragment) ++seqno % 0x1000;
  
  if (fragment > 0x0F) {
    printf("WARNING: Fragment number exceeded maximum of 15, resetting to 0.\n");
    fragment = 0;
  }
  
  hdr->type = type;
  
  hdr->flags = 0x00;
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
      memcpy((pkt->data) + (sizeof(struct ieee_hdr)), source.ether_octet, ETHER_ADDR_LEN);
      break;
    default:
      printf("ERROR: DS Flags invalid, use only a, f, t or w!\n");
      exit(-1);
  }
  
  hdr->duration = htobe16(duration);
  
  hdr->frag_seq = seqno & (fragment << 12);
}