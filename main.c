
#include <stdio.h>

#include "ndn-re.h"
#include "../ndn-lite/encode/name.h"
#include "ndn-trust-schema.h"

int main() {

  printf("This is a test of a potential schematized trust implementation.\n");
  printf("----------------------------------------------------------------\n\n");
  
  /* char test_rule_string[] = "/<test>/<>/<>*\/(<>)"; */
  char test_rule_string_1[] = "/<test>";
  char test_rule_string_2[] = "/<>";
  char test_rule_string_3[] = "/<>*";
  char test_rule_string_4[] = "/(<>)";
  char test_rule_string_5[] = "/[test]";
  char test_rule_string_6[] = "function(\\2)";
  ndn_trust_schema_rule_t test_rule;
  ndn_trust_schema_rule_from_string(&test_rule, test_rule_string_1, sizeof(test_rule_string_1));
  ndn_trust_schema_rule_from_string(&test_rule, test_rule_string_2, sizeof(test_rule_string_2));
  ndn_trust_schema_rule_from_string(&test_rule, test_rule_string_3, sizeof(test_rule_string_3));
  ndn_trust_schema_rule_from_string(&test_rule, test_rule_string_4, sizeof(test_rule_string_4));
  ndn_trust_schema_rule_from_string(&test_rule, test_rule_string_5, sizeof(test_rule_string_5));
  ndn_trust_schema_rule_from_string(&test_rule, test_rule_string_6, sizeof(test_rule_string_6));
  
}
