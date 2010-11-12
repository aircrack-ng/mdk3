#ifndef HAVE_ATTACKS_H
#define HAVE_ATTACKS_H

#include "dummy.h"

typedef void  (*fp) (void);
typedef char  (*fpc)(void);
typedef void* (*fpo)(int, char **);

struct attacks {
  /* void  */ fp print_shorthelp; /* (void) */
  /* void  */ fp print_longhelp; /* (void) */
  /* void* */ fpo parse_options; /* (int argc, char *argv[]) - Each attack parses its own options and returns a pointer to some struct,
				 //                            that contains their parsed result. If parsing fail, return NULL, mdk will exit! */
  
  char mode_identifier; /* A character to identify the mode: mdk3 <interface> MODE */
  char *attack_name; /* The name of this attack */
};

struct attacks *load_attacks(int *count);

int attack_count;

#endif