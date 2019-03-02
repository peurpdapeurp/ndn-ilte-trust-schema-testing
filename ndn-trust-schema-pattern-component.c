
#include "ndn-trust-schema-pattern-component.h"

#include <string.h>

#include "../ndn-lite/ndn-constants.h"
#include "../ndn-lite/ndn-error-code.h"

int
ndn_trust_schema_pattern_component_from_string(ndn_trust_schema_pattern_component_t* component, const char* string, uint32_t size)
{
  
  if (size+1 > NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE)
    return NDN_OVERSIZE;
  
  char temp_pattern_comp_string_arr[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE];

  memcpy(temp_pattern_comp_string_arr, string, size);
  temp_pattern_comp_string_arr[size] = '\0';
  
  int ret_val = -1;
  
  uint32_t string_size = string[size - 1] == '\0' ? size-1 : size;

  uint32_t type = _probe_trust_schema_pattern_component_type(temp_pattern_comp_string_arr, size);

  if (type == NDN_TRUST_SCHEMA_PATTERN_COMPONENT_UNRECOGNIZED_TYPE)
    return type;

  switch (type) {
  case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT:
    component->type = type;
    memcpy(component->value, string+1, size-2);
    component->size = size-2;
    break;
  case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT:
    component->type = type;
    break;
  case NDN_TRUST_SCHEMA_SUBPATTERN_INDEX:
    component->type = type;
    *component->value = ((int) string[1]) - '0';
    component->size = 1;
    break;
  case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE:
    component->type = type;
    break;
  case NDN_TRUST_SCHEMA_WILDCARD_SPECIALIZER:
    component->type = type;
    memcpy(component->value, string+1, size-2);
    component->size = size-2;
    break;
  case NDN_TRUST_SCHEMA_RULE_REF:
    ret_val = re_match(_rule_ref_args_rgxp, temp_pattern_comp_string_arr);
    if (ret_val == TINY_REGEX_C_FAIL) {
      return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
    }
    component->type = type;
    break;
  default:
    return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
  }

  return 0;
  
}

int
ndn_trust_schema_pattern_component_compare(const ndn_trust_schema_pattern_component_t *pattern_component, const name_component_t *name_component) {
  
  // allocate arrays for checking wildcard specializers
  char temp_wildcard_specializer_string_arr[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE];  
  char temp_name_component_string_arr[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE];
  
  switch (pattern_component->type) {
  case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT:
    return (memcmp(pattern_component->value, name_component->value, pattern_component->size) == 0 &&
	    pattern_component->size == name_component->size) ? 0 : -1;	      
  case NDN_TRUST_SCHEMA_WILDCARD_SPECIALIZER:
    memcpy(temp_wildcard_specializer_string_arr, pattern_component->value, pattern_component->size);
    temp_wildcard_specializer_string_arr[pattern_component->size] = '\0';
    memcpy(temp_name_component_string_arr, name_component->value, name_component->size);
    temp_name_component_string_arr[name_component->size] = '\0';
    int ret_val = re_match(temp_wildcard_specializer_string_arr, temp_name_component_string_arr);
    return (ret_val != TINY_REGEX_C_FAIL) ? 0 : -1;
  case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT:
  case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE:
    return 0;
  case NDN_TRUST_SCHEMA_SUBPATTERN_INDEX:
  case NDN_TRUST_SCHEMA_RULE_REF:
    return -1;
  default:
    return -1;
  }
  return -1;

}
