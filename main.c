
#include <stdio.h>

#include "../ndn-lite/encode/name.h"
#include "../ndn-lite/ndn-error-code.h"
#include "ndn-trust-schema.h"

int main() {

  int ret_val = -1;
  
  printf("This is a test of a potential schematized trust implementation.\n");
  printf("----------------------------------------------------------------\n\n");
  
  char test_data_pattern_string[] = "<test><test><test>";
  char test_key_pattern_string[] = "<test><test><test>";
  char test_data_name_pattern_string_1[] = "/test/test/test";
  char test_data_name_pattern_string_2[] = "/test/test/fail";
  char test_key_name_pattern_string_1[] = "/test/test/test";
  char test_key_name_pattern_string_2[] = "/test/test/fail";

  ndn_trust_schema_rule_t test_rule;
  ndn_name_t test_data_name_1;
  ndn_name_t test_data_name_2;
  ndn_name_t test_key_name_1;
  ndn_name_t test_key_name_2;

  ret_val = ndn_name_from_string(&test_data_name_1, test_data_name_pattern_string_1, sizeof(test_data_name_pattern_string_1));
  if (ret_val != NDN_SUCCESS) {
    printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val);
  }

  ret_val = ndn_name_from_string(&test_data_name_2, test_data_name_pattern_string_2, sizeof(test_data_name_pattern_string_2));
  if (ret_val != NDN_SUCCESS) {
    printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val);
  }
  
  ret_val = ndn_name_from_string(&test_key_name_1, test_key_name_pattern_string_1, sizeof(test_key_name_pattern_string_1));
  if (ret_val != NDN_SUCCESS) {
    printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val);
  }
  ret_val = ndn_name_from_string(&test_key_name_2, test_key_name_pattern_string_2, sizeof(test_key_name_pattern_string_2));
  if (ret_val != NDN_SUCCESS) {
    printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val);
  }
  ret_val = ndn_trust_schema_rule_from_strings(&test_rule,
					       test_data_pattern_string, sizeof(test_data_pattern_string),
					       test_key_pattern_string, sizeof(test_key_pattern_string));
  if (ret_val != NDN_SUCCESS) {
    printf("Call to ndn_trust_schema_rule_from_strings failed, error code: %d\n", ret_val);
  }  
  printf("\n");
  
  ret_val = ndn_trust_schema_verify_data_name_key_name_pair(&test_rule, &test_data_name_1, &test_key_name_1);
  if (ret_val != 0) {
    printf("Call to ndn_trust_schema_verify_key_name failed for test data name 1, test key name 1, error code: %d\n", ret_val);
  }
  
  ret_val = ndn_trust_schema_verify_data_name_key_name_pair(&test_rule, &test_data_name_2, &test_key_name_1);
  if (ret_val != 0) {
    printf("Call to ndn_trust_schema_verify_key_name failed for test data name 2, test key name 1, error code: %d\n", ret_val);
  }

}
