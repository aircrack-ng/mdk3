#include <stdio.h>
#include <string.h>

#include "beacon_flood.h"

#define BEACON_FLOOD_MODE 'b'
#define BEACON_FLOOD_NAME "Beacon Flooding"

struct beacon_flood_options {
  int option_count;
};

void beacon_flood_shorthelp()
{
  printf("  Sends beacon frames to show fake APs at clients.\n");
  printf("  This can sometimes crash network scanners and even drivers!\n");
}

void beacon_flood_longhelp()
{
  printf( "      Sends beacon frames to generate fake APs at clients.\n"
	  "      This can sometimes crash network scanners and drivers!\n"
	  "      OPTIONS:\n"
	  "      -n <ssid>\n"
	  "         Use SSID <ssid> instead of randomly generated ones\n"
	  "      -f <filename>\n"
	  "         Read SSIDs from file\n"
	  "      -v <filename>\n"
	  "         Read MACs and SSIDs from file. See example file!\n"
	  "      -t <adhoc>\n"
	  "         -d 1 = Create only Ad-Hoc network\n"
	  "         -d 0 = Create only Managed (AP) networks\n"
	  "         without this option, both types are generated\n"
	  "      -w <encryptions>\n"
	  "         Select which type of encryption the fake networks shall have\n"
	  "         Valid options: n = No Encryption, w = WEP, t = TKIP (WPA), a = AES (WPA2)\n"
	  "         You can select multiple types, i.e. \"-w wta\" will only create WEP and WPA networks\n" 
	  "      -b <bitrate>\n"
	  "         Select if 11 Mbit (b) or 54 MBit (g) networks are created\n"
	  "         Without this option, both types will be used.\n"
	  "      -m\n"
	  "         Use valid accesspoint MAC from built-in OUI database\n"
	  "      -h\n"
	  "         Hop to channel where network is spoofed\n"
	  "         This is more effective with some devices/drivers\n"
	  "         But it reduces packet rate due to channel hopping.\n"
	  "      -c <chan>\n"
	  "         Create fake networks on channel <chan>. If you want your card to\n"
	  "         hop on this channel, you have to set -h option, too.\n"
	  "      -s <pps>\n"
	  "         Set speed in packets per second (Default: 50)\n");
}

void *beacon_flood_parse(int argc, char *argv[]) {
  int i;
  struct beacon_flood_options *bopt = malloc(sizeof(struct beacon_flood_options));
  

  
  return (void *) bopt;
}

struct attacks load_beacon_flood() {
  struct attacks this_attack;
  char *beacon_flood_name = malloc(strlen(BEACON_FLOOD_NAME) + 1);
  strcpy(beacon_flood_name, BEACON_FLOOD_NAME);

  this_attack.print_shorthelp = (fp) beacon_flood_shorthelp;
  this_attack.print_longhelp = (fp) beacon_flood_longhelp;
  this_attack.parse_options = (fpo) beacon_flood_parse;
  this_attack.mode_identifier = BEACON_FLOOD_MODE;
  this_attack.attack_name = beacon_flood_name;

  return this_attack;
}
