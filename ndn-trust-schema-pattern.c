
#include "ndn-trust-schema-pattern.h"

#include <stdio.h>

int
ndn_trust_schema_pattern_from_string(ndn_trust_schema_pattern_t* pattern, const char* string, uint32_t size) {
  
  int ret_val = -1;
  
  pattern->components_size = 0;

  // first check if it's a rule reference
  if (string[0] != '<' && string[0] != '(' && string[0] != '[') {
    ndn_trust_schema_pattern_component_t component;
    ret_val = ndn_trust_schema_pattern_component_from_string(&component, string, size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = ndn_trust_schema_pattern_append_component(pattern, &component);
    if (ret_val != NDN_SUCCESS) return ret_val;
    return 0;
  }

  int i = 0;
  const char * current_string = string;
  
  // iterate through the schema pattern
  while (i+1 < size-1) {

    printf("Value of current_string: %s\n", current_string);
    
    int pattern_comp_end_index = -1;
    
    if (current_string[0] == '<') {
      printf("In ndn_trust_schema_pattern_from_string, found an element of pattern beginning with <.\n");
      pattern_comp_end_index = re_match("^<>\\*", current_string);
      if (pattern_comp_end_index == TINY_REGEX_C_FAIL) {
	pattern_comp_end_index = re_match(">", current_string);
	if (pattern_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
	printf("In ndn_trust_schema_pattern_from_string, found a single wildcard or single name component.\n");
      }
      else {
	printf("In ndn_trust_schema_pattern_from_string, found a multiple wildcard.\n");
	pattern_comp_end_index += 2;
      }
    }
    else if (current_string[0] == '[') {
      printf("In ndn_trust_schema_pattern_from_string, found an element of pattern beginning with [.\n");
      pattern_comp_end_index = re_match("]", current_string);
      if (pattern_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
    }
    else if (current_string[0] == '(') {
      printf("In ndn_trust_schema_pattern_from_string, found an element of pattern beginning with (.\n");
      pattern_comp_end_index = re_match(")", current_string);
      if (pattern_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
    }
    else {
      if (current_string[0] == '\0')
	return 0;
      else
	return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
    }

    int pattern_comp_string_len = pattern_comp_end_index - i + 1;

    ndn_trust_schema_pattern_component_t component;
    ret_val = ndn_trust_schema_pattern_component_from_string(&component, current_string, pattern_comp_string_len);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = ndn_trust_schema_pattern_append_component(pattern, &component);
    if (ret_val != NDN_SUCCESS) return ret_val;

    current_string += pattern_comp_end_index + 1;
    
  }
  
  return 0;

}
