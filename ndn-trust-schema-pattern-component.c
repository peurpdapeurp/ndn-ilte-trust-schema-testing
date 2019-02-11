
#include "ndn-trust-schema-pattern-component.h"

#include <string.h>


#include "../ndn-lite/ndn-constants.h"
#include "../ndn-lite/ndn-error-code.h"

int
ndn_trust_schema_pattern_component_from_string(ndn_trust_schema_pattern_component_t* component, const char* string, uint32_t size)
{

  char function_msg_prefix[] = "In ndn_trust_schema_pattern_component_from_string, ";

  printf("In ndn_trust_schema_pattern_component_from_string, size of string passed in: %d\n", size);
  printf("In ndn_trust_schema_pattern_component_from_string, string passed in: %.*s\n", size, string);

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
    printf("%sgot a single name component.\n", function_msg_prefix);
    component->type = type;
    memcpy(component->value, string+1, size-2);
    component->size = size-2;
    break;
  case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT:
    printf("%sgot a wildcard name component.\n", function_msg_prefix);
    component->type = type;
    break;
  case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE:
    printf("%sgot a wildcard name component sequence.\n", function_msg_prefix);
    component->type = type;
    break;
  case NDN_TRUST_SCHEMA_SUBPATTERN_MATCH:
    printf("%sgot a subpattern match.\n", function_msg_prefix);
    printf("%ssubpattern query found inside of subpattern match: %.*s\n", function_msg_prefix, size-3, temp_pattern_comp_string_arr+2);
    component->type = type;
    break;
  case NDN_TRUST_SCHEMA_WILDCARD_SPECIALIZER:
    printf("%sgot a function reference.\n", function_msg_prefix);
    printf("%sname of function being referenced: %.*s\n", function_msg_prefix, size-3, temp_pattern_comp_string_arr+2);
    component->type = type;
    break;
  case NDN_TRUST_SCHEMA_RULE_REF:
    printf("%sgot a rule reference.\n", function_msg_prefix);
    ret_val = re_match(_rule_ref_args_rgxp, temp_pattern_comp_string_arr);
    if (ret_val == TINY_REGEX_C_FAIL) {
      return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
    }
    printf("%sstarting index of rule reference's arguments: %d\n", function_msg_prefix, ret_val);
    printf("%srule reference's arguments: %.*s\n", function_msg_prefix, size-2-ret_val, temp_pattern_comp_string_arr+ret_val);
    component->type = type;
    break;
  default:
    return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
  }

  return 0;
  
}
