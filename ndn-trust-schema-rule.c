
#include "ndn-trust-schema-rule.h"

#include <stdio.h>

int
ndn_trust_schema_rule_from_strings(ndn_trust_schema_rule_t* rule,
				     const char* data_name_pattern_string, uint32_t data_name_pattern_string_size,
				     const char* key_name_pattern_string, uint32_t key_name_pattern_string_size) {

  const char function_msg_prefix[] = "In ndn_trust_schema_rule_from_strings, ";
  int ret_val = -1;
  
  ret_val = ndn_trust_schema_pattern_from_string(&rule->data_pattern, data_name_pattern_string, data_name_pattern_string_size);
  if (ret_val != 0) {
    return ret_val;
  }

  for (int i = 0; i < rule->data_pattern.components_size; i++) {
    printf("Type of data pattern's %dth component: ", i);
    if (rule->data_pattern.components[i].type == NDN_TRUST_SCHEMA_PADDING_COMPONENT) {
      printf("padding");
    }
    else if (rule->data_pattern.components[i].type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT) {
      printf("single wildcard");    
    }
    else if (rule->data_pattern.components[i].type == NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT) {
      printf("single name component");
    }
    else if (rule->data_pattern.components[i].type == NDN_TRUST_SCHEMA_WILDCARD_SPECIALIZER) {
      printf("wildcard specializer");
    }
    else if (rule->data_pattern.components[i].type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE) {
      printf("wildcard sequence");
    }
    printf("\n");
    
  }

  printf("--\n\n");
  
  ret_val = ndn_trust_schema_pattern_from_string(&rule->key_pattern, key_name_pattern_string, key_name_pattern_string_size);
  if (ret_val != 0) {
    return ret_val;
  }

  printf("--\n\n");

  return 0;
  
}
