#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "attacks/attacks.h"
#include "osdep.h"

#define VERSION "v7"
#define VERSION_COOL "OMG! He cleaned his code!"

char *mdk3_help = "MDK 3.0 " VERSION " - \"" VERSION_COOL "\"\n"
		  "by ASPj of k2wrlz, using the osdep library from aircrack-ng\n"
		  "And with lots of help from the great aircrack-ng community:\n"
		  "Antragon, moongray, Ace, Zero_Chaos, Hirte, thefkboss, ducttape,\n"
		  "telek0miker, Le_Vert, sorbo, Andy Green, bahathir, Dawid Gajownik\n"
		  "and Ruslan Nabioullin\n"
		  "THANK YOU!\n\n"
		  "MDK is a proof-of-concept tool to exploit common IEEE 802.11 protocol weaknesses.\n"
		  "IMPORTANT: It is your responsibility to make sure you have permission from the\n"
		  "network owner before running MDK against it.\n\n"
		  "This code is licenced under the GPLv2 or later\n\n"
		  "MDK USAGE:\n"
		  "mdk3 <interface> <attack_mode> [attack_options]\n\n"
		  "Try mdk3 --fullhelp for all attack options\n"
		  "Try mdk3 --help <attack_mode> for info about one attack only\n\n";

void print_help_and_die(struct attacks *att, int att_cnt, char full, char *add_msg) {
  int i;
  
  printf("%s\n", mdk3_help);
  printf("Loaded %d attack modules\n\n", att_cnt);

  for(i=0; i<att_cnt; i++) {
    printf("ATTACK MODE %c: %s\n", att[i].mode_identifier, att[i].attack_name);
    att[i].print_shorthelp();
  }
  
  if (full) {
    printf("\nFULL OPTIONS:\n");
    for(i=0; i<att_cnt; i++) {
      printf("\nATTACK MODE %c: %s\n", att[i].mode_identifier, att[i].attack_name);
      att[i].print_longhelp();
    }
  }
  
  if (add_msg) printf("\nERROR: %s\n", add_msg);
  
  exit(1);
}

int main(int argc, char *argv[]) {
  struct attacks *a, *cur_attack = NULL;
  void *cur_options;
  int i, att_cnt;
      
  a = load_attacks(&att_cnt);
  
  if (geteuid() != 0) print_help_and_die(a, att_cnt, 0, "mdk3 requires root privileges.");

  if (argc < 2) print_help_and_die(a, att_cnt, 0, NULL);
  
  if (! strcmp(argv[1], "--fullhelp")) print_help_and_die(a, att_cnt, 1, NULL);
  
  if (argc < 3) print_help_and_die(a, att_cnt, 0, NULL);
  
  if (strlen(argv[2]) != 1) print_help_and_die(a, att_cnt, 0, "Attack Mode is only a single character!\n");
  
  for(i=0; i<att_cnt; i++) {
    if (argv[2][0] == a[i].mode_identifier) cur_attack = a + i;
  }
  
  if (cur_attack == NULL) print_help_and_die(a, att_cnt, 0, "Invalid Attack Mode\n");
  
  if (! strcmp(argv[1], "--help")) { cur_attack->print_longhelp(); return 0; }
  
  if (osdep_start(argv[1])) {
    printf("Starting OSDEP on %s failed\n", argv[1]);
    return 2;
  }
  
  /* drop privileges */
  setuid(getuid());

  cur_options = cur_attack->parse_options(argc - 3, argv + 3);
  if (!cur_options) return 1;
  
  printf("Parsing done, start threads, send packets, perform checks\n");
  
  return 0;
}
