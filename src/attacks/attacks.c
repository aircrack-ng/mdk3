#include <string.h>

#include "attacks.h"

int attack_count = 2;

struct attacks *load_attacks(int *count) {
  struct attacks *attacks = malloc(sizeof(struct attacks) * attack_count);
  
  attacks[0] = load_dummy();
  attacks[1] = load_beacon_flood();
  
  *count = attack_count;
  return attacks;
}