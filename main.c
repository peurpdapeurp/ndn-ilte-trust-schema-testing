
#include <stdio.h>

#include "../ndn-lite/encode/name.h"
#include "../ndn-lite/ndn-error-code.h"
#include "ndn-trust-schema.h"

int main() {

  int ret_val = -1;
  
  printf("This is a test of a potential schematized trust implementation.\n");
  printf("----------------------------------------------------------------\n\n");
  
  char test_rule_string[] = "<test><test><test>";
  char test_key_name_string_1[] = "/test/test/test";
  char test_key_name_string_2[] = "/test/test/fail";
  char test_data_name_string[] = "/test/data/name";

  ndn_trust_schema_rule_t test_rule;
  ndn_name_t test_key_name_1;
  ndn_name_t test_key_name_2;
  ndn_name_t test_data_name;
  
  ret_val = ndn_name_from_string(&test_key_name_1, test_key_name_string_1, sizeof(test_key_name_string_1));
  if (ret_val != NDN_SUCCESS) {
    printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val);
  }
  ret_val = ndn_name_from_string(&test_key_name_2, test_key_name_string_2, sizeof(test_key_name_string_2));
  if (ret_val != NDN_SUCCESS) {
    printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val);
  }
  
  ret_val = ndn_name_from_string(&test_data_name, test_data_name_string, sizeof(test_data_name_string));
  if (ret_val != NDN_SUCCESS) {
    printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val);
  }

  ret_val = ndn_trust_schema_rule_from_string(&test_rule, test_rule_string, sizeof(test_rule_string));
  if (ret_val != NDN_SUCCESS) {
    printf("Call to ndn_trust_schema_rule_from_string failed, error code: %d\n", ret_val);
  }
  for (int i = 0; i < test_rule.components_size; i++) {
    printf("Component %d test rule, type: %d\n", i, test_rule.components[i].type);
  }
  printf("\n");
  
  printf("\n");
  
  ret_val = ndn_trust_schema_verify_key_name(&test_rule, &test_data_name, &test_key_name_1);
  if (ret_val != 0) {
    printf("Call to ndn_trust_schema_verify_key_name failed for test key name 1, error code: %d\n", ret_val);
  }
  
  ret_val = ndn_trust_schema_verify_key_name(&test_rule, &test_data_name, &test_key_name_2);
  if (ret_val != 0) {
    printf("Call to ndn_trust_schema_verify_key_name failed for test key name 2, error code: %d\n", ret_val);
  }
  
}

  /* char test_rule_string[] = "<test><><>*(<>)"; */
  /* char test_rule_string_1[] = "<test>"; */
  /* char test_rule_string_2[] = "<>"; */
  /* char test_rule_string_3[] = "<>*"; */
  /* char test_rule_string_4[] = "(<>)"; */
  /* char test_rule_string_5[] = "[test]"; */
  /* char test_rule_string_6[] = "function(\\2)"; */

  /* ret_val = ndn_trust_schema_rule_from_string(&test_rule, test_rule_string, sizeof(test_rule_string)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_trust_schema_rule_from_string failed, error code: %d\n", ret_val); */
  /* }   */
  /* for (int i = 0; i < test_rule.components_size; i++) { */
  /*   printf("Component %d test rule, type: %d\n", i, test_rule.components[i].type); */
  /* } */
  /* printf("\n"); */
  
  /* ret_val = ndn_trust_schema_rule_from_string(&test_rule, test_rule_string_1, sizeof(test_rule_string_1)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_trust_schema_rule_from_string failed, error code: %d\n", ret_val); */
  /* }   */
  /* for (int i = 0; i < test_rule.components_size; i++) { */
  /*   printf("Component %d test rule, type: %d\n", i, test_rule.components[i].type); */
  /* } */
  /* printf("\n"); */
  
  /* ret_val = ndn_trust_schema_rule_from_string(&test_rule, test_rule_string_2, sizeof(test_rule_string_2)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_trust_schema_rule_from_string failed, error code: %d\n", ret_val); */
  /* } */
  /* for (int i = 0; i < test_rule.components_size; i++) { */
  /*   printf("Component %d test rule, type: %d\n", i, test_rule.components[i].type); */
  /* } */
  /* printf("\n"); */
  
  /* ret_val = ndn_trust_schema_rule_from_string(&test_rule, test_rule_string_3, sizeof(test_rule_string_3)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_trust_schema_rule_from_string failed, error code: %d\n", ret_val); */
  /* } */
  /* for (int i = 0; i < test_rule.components_size; i++) { */
  /*   printf("Component %d test rule, type: %d\n", i, test_rule.components[i].type); */
  /* } */
  /* printf("\n"); */
  
  /* ret_val = ndn_trust_schema_rule_from_string(&test_rule, test_rule_string_4, sizeof(test_rule_string_4)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_trust_schema_rule_from_string failed, error code: %d\n", ret_val); */
  /* } */
  /* for (int i = 0; i < test_rule.components_size; i++) { */
  /*   printf("Component %d test rule, type: %d\n", i, test_rule.components[i].type); */
  /* } */
  /* printf("\n"); */
  
  /* ret_val = ndn_trust_schema_rule_from_string(&test_rule, test_rule_string_5, sizeof(test_rule_string_5)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_trust_schema_rule_from_string failed, error code: %d\n", ret_val); */
  /* } */
  /* for (int i = 0; i < test_rule.components_size; i++) { */
  /*   printf("Component %d test rule, type: %d\n", i, test_rule.components[i].type); */
  /* } */
  /* printf("\n"); */
  
  /* ret_val = ndn_trust_schema_rule_from_string(&test_rule, test_rule_string_6, sizeof(test_rule_string_6)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_trust_schema_rule_from_string failed, error code: %d\n", ret_val); */
  /* } */
  /* for (int i = 0; i < test_rule.components_size; i++) { */
  /*   printf("Component %d test rule, type: %d\n", i, test_rule.components[i].type); */
  /* } */
  /* printf("\n"); */
