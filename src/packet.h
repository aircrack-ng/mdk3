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
  uint8_t frag_seq;
} __attribute__((packed));

