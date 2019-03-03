
#include "ndn-trust-schema-pattern-component.h"

#include <string.h>
#include <stdlib.h>

#include "../ndn-lite/ndn-constants.h"
#include "../ndn-lite/ndn-error-code.h"

int
ndn_trust_schema_pattern_component_from_string(ndn_trust_schema_pattern_component_t* component, const char* string, uint32_t size)
{
  
  if (size+1 > NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE)
    return NDN_OVERSIZE;
  
  char temp_pattern_comp_string_arr[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE];
  char subpattern_idx_string[3];
  subpattern_idx_string[2] = '\0';

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
  case NDN_TRUST_SCHEMA_RULE_REF: {
    int rule_ref_args_begin_idx = re_match(_rule_ref_args_rgxp, temp_pattern_comp_string_arr);
    if (rule_ref_args_begin_idx == TINY_REGEX_C_FAIL) {
      return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
    }
    printf("Value of rule_ref_args_begin_idx: %d\n", rule_ref_args_begin_idx);
    if (rule_ref_args_begin_idx > NDN_TRUST_SCHEMA_RULE_NAME_MAX_LENGTH)
      return NDN_OVERSIZE;
    memset(component->value + NDN_TRUST_SCHEMA_RULE_REF_ARGS_BIT_FIELD_OFFSET,
	   0, NDN_TRUST_SCHEMA_RULE_REFERENCE_ARGS_BIT_FIELD_SIZE);
    if (rule_ref_args_begin_idx > size ||
	temp_pattern_comp_string_arr[rule_ref_args_begin_idx] != '(')
      return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;

    memcpy(component->value, string, rule_ref_args_begin_idx);
    
    int rule_ref_subpattern_arg_idx = rule_ref_args_begin_idx+1;
    uint16_t *rule_ref_args_bit_field = (uint16_t *) (component->value + NDN_TRUST_SCHEMA_RULE_REF_ARGS_BIT_FIELD_OFFSET);
    while (1) {
      int current_subpattern_arg_idx = re_match(_rule_ref_subpattern_index_rgxp, temp_pattern_comp_string_arr + rule_ref_subpattern_arg_idx);
      if (current_subpattern_arg_idx == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
      rule_ref_subpattern_arg_idx += current_subpattern_arg_idx + 1;
      int current_subpattern_arg_end_idx = re_match(",", temp_pattern_comp_string_arr + rule_ref_subpattern_arg_idx);
      if (current_subpattern_arg_end_idx == TINY_REGEX_C_FAIL) {
	current_subpattern_arg_end_idx = re_match(")", temp_pattern_comp_string_arr + rule_ref_subpattern_arg_idx);
	if (current_subpattern_arg_end_idx == TINY_REGEX_C_FAIL ||
	    rule_ref_subpattern_arg_idx + current_subpattern_arg_end_idx != size-1) {
	  printf("Failure when trying to find ). rule_ref_subpattern_arg_idx + current_subpattern_arg_end_idx (%d), size-1 (%d)\n",
		 rule_ref_subpattern_arg_idx + current_subpattern_arg_end_idx, size);
	  return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
	}
      }
      if (current_subpattern_arg_end_idx > 2) {
	printf("parsing error because current_subpattern_arg_end_idx (%d) > 2\n", current_subpattern_arg_end_idx);
	return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
      }
      printf("Value of current_subpattern_arg_end_idx: %d\n", current_subpattern_arg_end_idx);
      printf("Value of temp_pattern_comp_string_arr, starting from rule_ref_subpattern_arg_idx: %s\n",
	     temp_pattern_comp_string_arr + rule_ref_subpattern_arg_idx);
      if (current_subpattern_arg_end_idx == 1) {
	memcpy(subpattern_idx_string, temp_pattern_comp_string_arr + rule_ref_subpattern_arg_idx, 1);
        subpattern_idx_string[1] = '\0';
      }
      else if (current_subpattern_arg_end_idx == 2)
	memcpy(subpattern_idx_string, temp_pattern_comp_string_arr + rule_ref_subpattern_arg_idx, current_subpattern_arg_end_idx);
      else
	return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
      printf("Value of subpattern_idx_string: %s\n", subpattern_idx_string);
      int idx = atoi(subpattern_idx_string);
      printf("Value of idx: %d\n", idx);
      if (idx > NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES - 1) {
	return NDN_TRUST_SCHEMA_INVALID_SUBPATTERN_INDEX_REFERENCE;
      }
      *(rule_ref_args_bit_field) |=
	(uint16_t) (0x01 << (NDN_TRUST_SCHEMA_RULE_REFERENCE_ARGS_BIT_FIELD_SIZE * 8 - idx - 1));
      printf("Value of current_subpattern_arg_idx: %d\n", current_subpattern_arg_idx);
      printf("Value of rule ref args bit field: %d\n", (uint16_t) *(component->value + NDN_TRUST_SCHEMA_RULE_REF_ARGS_BIT_FIELD_OFFSET));
      printf("Value of rule_ref_subpattern_arg_idx: %d\n", rule_ref_subpattern_arg_idx);
      printf("Value of size: %d\n", size);
      if (rule_ref_subpattern_arg_idx >= size-3) {
	printf("Breaking, since %d was >= %d\n", rule_ref_subpattern_arg_idx, size-3);
	break;
      }
    }

    printf("After while loop in rule reference parser.\n");
    
    component->type = type;
    component->size = rule_ref_args_begin_idx;

    printf("Value of rule ref args bit field before exiting: %d\n",
	   *rule_ref_args_bit_field);
    
    break;
  }
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
