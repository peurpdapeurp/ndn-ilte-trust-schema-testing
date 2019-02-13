
#include "ndn-trust-schema.h"

#include "../ndn-lite/ndn-error-code.h"
#include "../ndn-lite/ndn-constants.h"

#include <stdbool.h>

void _check_name_against_pattern(bool *name_valid, const ndn_trust_schema_pattern_t *pattern, const ndn_name_t* name) {

  int pi = 0, ni = 0;
  
  while (pi < pattern->components_size && ni < name->components_size) {    
    switch (pattern->components[pi].type) {
    case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT:      
      if (memcmp(pattern->components[pi].value, name->components[ni].value, pattern->components[pi].size) != 0 ||
  	  pattern->components[pi].size != name->components[ni].size) {
  	*name_valid = false;
      }
      pi++;
      ni++;
      break;
    case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT:
      pi++;
      ni++;
      break;
    case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE:
      break;
    }

    if (!(*name_valid))
      break;
  }
}

int
ndn_trust_schema_verify_data_name_key_name_pair(const ndn_trust_schema_rule_t* rule, const ndn_name_t* data_name, const ndn_name_t* key_name) {

  const char function_msg_prefix[] = "In ndn_trust_schema_verify_key_name, ";
  
  bool data_name_valid = true;
  bool key_name_valid = true;

  _check_name_against_pattern(&data_name_valid, &rule->data_pattern, data_name);
  _check_name_against_pattern(&key_name_valid, &rule->key_pattern, key_name);
  
  return (data_name_valid && key_name_valid) ? 0 : -1;
  
}
