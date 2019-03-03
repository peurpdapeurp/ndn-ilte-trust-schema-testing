
#include <stdio.h>

#include "trust-schema-tests.h"
#include "ndn-trust-schema-rule.h"

int main() {

  printf("Running trust schema unit tests.\n");

  if (run_trust_schema_tests())
    printf("ALL TRUST SCHEMA UNIT TESTS SUCCEEDED.\n");
  else
    printf("ONE OR MORE TRUST SCHEMA UNIT TESTS FAILED.\n");
  
}
