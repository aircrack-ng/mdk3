#include <stdio.h>
#include <string.h>

#include "dummy.h"

#define DUMMY_MODE 'D'
#define DUMMY_NAME "An empty dummy attack"

struct dummy_options {
  int option_count;
};

void dummy_shorthelp()
{
  printf("  dummy call short help\n");
}

void dummy_longhelp()
{
  printf("  dummy call 2 LONG HELP\n");
}

void *dummy_parse(int argc, char *argv[]) {
  int i;
  struct dummy_options *dopt = malloc(sizeof(struct dummy_options));
  
  for (i=0; i<argc; i++)
    printf("parse: %d: %s\n", i, argv[i]);
  
  if (argc < 3) {
    printf("Missing arguments (need at least 3)!\n");
    return NULL;
  }
  
  dopt->option_count = argc;
  
  return (void *) dopt;
}

struct attacks load_dummy() {
  struct attacks this_attack;
  char *dummy_name = malloc(strlen(DUMMY_NAME) + 1);
  strcpy(dummy_name, DUMMY_NAME);

  this_attack.print_shorthelp = (fp) dummy_shorthelp;
  this_attack.print_longhelp = (fp) dummy_longhelp;
  this_attack.parse_options = (fpo) dummy_parse;
  this_attack.mode_identifier = DUMMY_MODE;
  this_attack.attack_name = dummy_name;

  return this_attack;
}
