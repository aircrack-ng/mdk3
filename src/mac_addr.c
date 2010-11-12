#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#include "manufactor.h"
#include "mac_addr.h"

char hex2char (char byte1, char byte2)
{
// Very simple routine to convert hexadecimal input into a byte
	char rv = 0;

	if (byte1 == '0') { rv = 0; }
	if (byte1 == '1') { rv = 16; }
	if (byte1 == '2') { rv = 32; }
	if (byte1 == '3') { rv = 48; }
	if (byte1 == '4') { rv = 64; }
	if (byte1 == '5') { rv = 80; }
	if (byte1 == '6') { rv = 96; }
	if (byte1 == '7') { rv = 112; }
	if (byte1 == '8') { rv = 128; }
	if (byte1 == '9') { rv = 144; }
	if (byte1 == 'A' || byte1 == 'a') { rv = 160; }
	if (byte1 == 'B' || byte1 == 'b') { rv = 176; }
	if (byte1 == 'C' || byte1 == 'c') { rv = 192; }
	if (byte1 == 'D' || byte1 == 'd') { rv = 208; }
	if (byte1 == 'E' || byte1 == 'e') { rv = 224; }
	if (byte1 == 'F' || byte1 == 'f') { rv = 240; }

	if (byte2 == '0') { rv += 0; }
	if (byte2 == '1') { rv += 1; }
	if (byte2 == '2') { rv += 2; }
	if (byte2 == '3') { rv += 3; }
	if (byte2 == '4') { rv += 4; }
	if (byte2 == '5') { rv += 5; }
	if (byte2 == '6') { rv += 6; }
	if (byte2 == '7') { rv += 7; }
	if (byte2 == '8') { rv += 8; }
	if (byte2 == '9') { rv += 9; }
	if (byte2 == 'A' || byte2 == 'a') { rv += 10; }
	if (byte2 == 'B' || byte2 == 'b') { rv += 11; }
	if (byte2 == 'C' || byte2 == 'c') { rv += 12; }
	if (byte2 == 'D' || byte2 == 'd') { rv += 13; }
	if (byte2 == 'E' || byte2 == 'e') { rv += 14; }
	if (byte2 == 'F' || byte2 == 'f') { rv += 15; }

	return rv;
}


struct ether_addr parse_mac(char *input)
{
// Parsing input MAC adresses like 00:00:11:22:aa:BB or 00001122aAbB

    unsigned char tmp[12] = "000000000000";
    int t;
    struct ether_addr mac_p;

    if (input[2] == ':') {
	memcpy(tmp   , input   , 2);
	memcpy(tmp+2 , input+3 , 2);
	memcpy(tmp+4 , input+6 , 2);
	memcpy(tmp+6 , input+9 , 2);
	memcpy(tmp+8 , input+12 , 2);
	memcpy(tmp+10, input+15 , 2);
    } else {
	memcpy(tmp, input, 12);
    }

    for (t=0; t<ETHER_ADDR_LEN; t++)
	mac_p.ether_addr_octet[t] = hex2char(tmp[2*t], tmp[2*t+1]);
 
    return mac_p;
}


struct ether_addr parse_half_mac(char *input)
{
// Parsing input half MAC adresses like 00:00:11 or 000011
// Octets 3 to 5 will be 0x00

    unsigned char tmp[6] = "000000";
    struct ether_addr mac_ph;
    int t;

    if (input[2] == ':') {
	memcpy(tmp   , input   , 2);
	memcpy(tmp+2 , input+3 , 2);
	memcpy(tmp+4 , input+6 , 2);
    } else {
	memcpy(tmp, input, 6);
    }

    for (t=0; t<3; t++)
	mac_ph.ether_addr_octet[t] = hex2char(tmp[2*t], tmp[2*t+1]);
    for (t=3; t<6; t++)
	mac_ph.ether_addr_octet[t] = 0x00;
    
    return mac_ph;
}


struct ether_addr generate_valid_mac(int type, int list_len)
{
    int t, pos;
    struct ether_addr mac_v;

    pos = random();
    pos = pos % list_len;

    // SAMPLE LINE
    // 000123000000/FFFFFF000000
    // 0 2 4 6 8 10 13 16 19 22

    if (type == 0) {
	for (t=0; t<ETHER_ADDR_LEN; t++) {
	    if (!memcmp(clients[pos]+(t*2+13), "FF", 2) || !memcmp(clients[pos]+(t*2+13), "ff", 2)) {
		mac_v.ether_addr_octet[t] = hex2char(clients[pos][t*2], clients[pos][t*2+1]);
	    } else mac_v.ether_addr_octet[t] = random();
	}
    } else {
	for (t=0; t<ETHER_ADDR_LEN; t++) {
	    if (!memcmp(accesspoints[pos]+(t*2+13), "FF", 2) || !memcmp(accesspoints[pos]+(t*2+13), "ff", 2)) {
		mac_v.ether_addr_octet[t] = hex2char(accesspoints[pos][t*2], accesspoints[pos][t*2+1]);
	    } else mac_v.ether_addr_octet[t] = random();
	}
    }

    return mac_v;
}


struct ether_addr generate_mac(enum mac_kind kind)
{
// Generate a random MAC adress
// kind : Which kind of MAC should be generated?
//    0 : random MAC
//    1 : valid client MAC
//    2 : valid accesspoint MAC

    struct ether_addr gmac;
    int t;

    for (t=0; t<ETHER_ADDR_LEN; t++)
        gmac.ether_addr_octet[t] = random();

    if (kind == MAC_KIND_CLIENT)
	gmac = generate_valid_mac(0, clients_count);
    if (kind == MAC_KIND_AP)
	gmac = generate_valid_mac(1, accesspoints_count);
    
    return gmac;
}


void increase_mac_adress(struct ether_addr *macaddr)
{
    macaddr->ether_addr_octet[2]++;
    if (macaddr->ether_addr_octet[2] == 0) {
	macaddr->ether_addr_octet[1]++;
	if (macaddr->ether_addr_octet[1] == 0) {
	    macaddr->ether_addr_octet[0]++;
	}
    }
}


struct ether_addr get_next_mac(struct ether_addr mac_base, struct ether_addr *mac_lower)
{
    static int pos = -2;
    static struct ether_addr lowb;
    static struct ether_addr upb;
    struct ether_addr mac_v;
    
    if (pos == -2) {
	MAC_SET_BCAST(lowb);
	MAC_SET_BCAST(upb);
	pos = -1;
    }

    if (MAC_IS_NULL(mac_base)) {	//Use internal database
	//Increase lower bytes
	increase_mac_adress(&lowb);
	//Get new upper bytes?
	if (! memcmp(lowb.ether_addr_octet, "\x00\x00\x00", 3)) {
	    //New pos in client list
	    pos++;
	    if (pos == clients_count) {
		MAC_SET_BCAST((*mac_lower));
		MAC_SET_NULL(mac_v);
		return mac_v;
	    }
	    //Filling the first three bytes
	    upb.ether_addr_octet[0] = hex2char(clients[pos][0], clients[pos][1]);
	    upb.ether_addr_octet[1] = hex2char(clients[pos][2], clients[pos][3]);
	    upb.ether_addr_octet[2] = hex2char(clients[pos][4], clients[pos][5]);
	}
	memcpy(mac_v.ether_addr_octet, upb.ether_addr_octet, 3);
	memcpy(mac_v.ether_addr_octet+3, lowb.ether_addr_octet, 3);
    } else {				//Use MAC given by user
	increase_mac_adress(&lowb);

	if (! MAC_IS_NULL(*mac_lower)) {	//Use start MAC given by user
	    memcpy(lowb.ether_addr_octet, mac_lower->ether_addr_octet, 3);
	    MAC_SET_NULL(*mac_lower);
	}

	if (! memcmp(lowb.ether_addr_octet, "\xFF\xFF\xFF", 3)) {
	    MAC_SET_BCAST((*mac_lower));
	    MAC_SET_NULL(mac_v);
	    return mac_v;
	}
	memcpy(mac_v.ether_addr_octet, mac_base.ether_addr_octet, 3);
	memcpy(mac_v.ether_addr_octet+3, lowb.ether_addr_octet, 3);
    }

    return mac_v;
}


void print_mac(struct ether_addr pmac)
{
    uint8_t *p = pmac.ether_addr_octet;
    
    printf("%02X:%02X:%02X:%02X:%02X:%02X", p[0], p[1], p[2], p[3], p[4], p[5]);
}