
#include "ndn-trust-schema.h"

#include "../ndn-lite/ndn-error-code.h"
#include "../ndn-lite/ndn-constants.h"

#include <stdio.h>

int
ndn_trust_schema_rule_from_string(ndn_trust_schema_rule_t* rule, const char* string, uint32_t size) {
  
  int ret_val = -1;
  
  rule->components_size = 0;

  // first check if it's a rule reference
  if (string[0] != '<' && string[0] != '(' && string[0] != '[') {
    ndn_trust_schema_rule_component_t component;
    ret_val = ndn_trust_schema_rule_component_from_string(&component, string, size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = ndn_trust_schema_rule_append_component(rule, &component);
    if (ret_val != NDN_SUCCESS) return ret_val;
    return 0;
  }

  int i = 0;
  const char * current_string = string;
  
  // iterate through the schema rule
  while (i+1 < size-1) {

    printf("Value of current_string: %s\n", current_string);
    
    int rule_comp_end_index = -1;
    
    if (current_string[0] == '<') {
      printf("In ndn_trust_schema_rule_from_string, found an element of rule beginning with <.\n");
      rule_comp_end_index = re_match("^<>\\*", current_string);
      if (rule_comp_end_index == TINY_REGEX_C_FAIL) {
	rule_comp_end_index = re_match(">", current_string);
	if (rule_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_RULE_COMPONENT_PARSING_ERROR;
	printf("In ndn_trust_schema_rule_from_string, found a single wildcard or single name component.\n");
      }
      else {
	printf("In ndn_trust_schema_rule_from_string, found a multiple wildcard.\n");
	rule_comp_end_index += 2;
      }
    }
    else if (current_string[0] == '[') {
      printf("In ndn_trust_schema_rule_from_string, found an element of rule beginning with [.\n");
      rule_comp_end_index = re_match("]", current_string);
      if (rule_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_RULE_COMPONENT_PARSING_ERROR;
    }
    else if (current_string[0] == '(') {
      printf("In ndn_trust_schema_rule_from_string, found an element of rule beginning with (.\n");
      rule_comp_end_index = re_match(")", current_string);
      if (rule_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_RULE_COMPONENT_PARSING_ERROR;
    }
    else {
      if (current_string[0] == '\0')
	return 0;
      else
	return NDN_TRUST_SCHEMA_RULE_COMPONENT_PARSING_ERROR;
    }

    int rule_comp_string_len = rule_comp_end_index - i + 1;

    ndn_trust_schema_rule_component_t component;
    ret_val = ndn_trust_schema_rule_component_from_string(&component, current_string, rule_comp_string_len);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = ndn_trust_schema_rule_append_component(rule, &component);
    if (ret_val != NDN_SUCCESS) return ret_val;

    current_string += rule_comp_end_index + 1;
    
  }
  
  return 0;

}
