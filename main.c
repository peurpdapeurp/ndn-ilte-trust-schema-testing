
#include <stdio.h>

#include "trust-schema-tests.h"
#include "ndn-trust-schema-rule-storage.h"
#include "ndn-trust-schema-rule.h"

static ndn_trust_schema_rule_t test_rule;
#define test_data_pattern_string "<>*<apple>"
#define test_key_pattern_string "<apple>"
static ndn_name_t test_data_name;
#define test_data_name_string "/apple/appletest/not_apple"
static ndn_name_t test_key_name;
#define test_key_name_string "/apple"

static ndn_trust_schema_rule_t test_rule_empty;

int main() {

  int ret_val = -1;
  
  printf("Running trust schema unit tests.\n");

  if (run_trust_schema_tests())
    printf("ALL TRUST SCHEMA UNIT TESTS SUCCEEDED.\n");
  else
    printf("ONE OR MORE TRUST SCHEMA UNIT TESTS FAILED.\n");
  
  ret_val = ndn_name_from_string(&test_data_name, test_data_name_string, strlen(test_data_name_string));
  
  ret_val = ndn_name_from_string(&test_key_name, test_key_name_string, strlen(test_key_name_string));
  
  ret_val = ndn_trust_schema_rule_from_strings(&test_rule,
  					       test_data_pattern_string, strlen(test_data_pattern_string),
  					       test_key_pattern_string, strlen(test_key_pattern_string));

  ret_val = ndn_trust_schema_verify_data_name_key_name_pair(&test_rule, &test_data_name, &test_key_name);

  ndn_rule_storage_init();
  printf("%d\n", sizeof(ndn_rule_storage_t));

  ret_val = ndn_rule_storage_add_rule("test_rule", &test_rule);
  if (ret_val != 0) {
    printf("ndn_rule_storage_add_rule failed, ret_val: %d\n", ret_val);
    return -1;
  }

  ret_val = ndn_rule_storage_get_rule("test_rule", &test_rule_empty);
  if (ret_val != 0) {
    printf("ndn_rule_storage_get_rule failed, ret_val: %d\n", ret_val);
    return -1;
  }
  
}

