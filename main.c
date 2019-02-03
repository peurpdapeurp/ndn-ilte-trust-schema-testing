
#include <stdio.h>

#include "ndn_re.h"
#include "../ndn-lite/encode/name.h"

int main() {

  printf("This is a test of a potential schematized trust implementation.\n");

  char test_name_string[] = "/test/name";
  ndn_name_t test_name;
  ndn_name_from_string(&test_name, test_name_string, sizeof(test_name_string));
  
  ndn_re_match(&test_name, &test_name);
  
}
