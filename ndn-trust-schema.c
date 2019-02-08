
#include "ndn-trust-schema.h"

#include "../ndn-lite/ndn-error-code.h"
#include "../ndn-lite/ndn-constants.h"

#include <stdio.h>
#include <stdbool.h>

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

int
ndn_trust_schema_verify_key_name(const ndn_trust_schema_rule_t* rule, const ndn_name_t* data_name, const ndn_name_t* key_name) {

  printf("In ndn_trust_schema_verify_key_name, printing the types of rule components in the rule:\n");
  for (int i = 0; i < rule->components_size; i++) {
    switch (rule->components[i].type) {
      printf("Rule component i was a");
    case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT:
      printf(" single name component, with value: %.*s\n", rule->components[i].size, rule->components[i].value);
      break;
    default:
      printf(" rule component other than a single name component.\n");
    }
  }
  printf("\n");

  printf("In ndn_trust_schema_verify_key_name, printing the data name:\n");
  for (int i = 0; i < data_name->components_size; i++) {
    printf("/%.*s", data_name->components[i].size, data_name->components[i].value);
  }
  printf("\n\n");

  printf("In ndn_trust_schema_verify_key_name, printing the key name:\n");
  for (int i = 0; i < key_name->components_size; i++) {
    printf("/%.*s", key_name->components[i].size, key_name->components[i].value);
  }
  printf("\n\n");

  bool key_name_valid = true;
  int ri = 0;
  int kni = 0;
  int dni = 0;

  printf("Rule components size: %d\n", rule->components_size);
  printf("key_name components size: %d\n", key_name->components_size);
  printf("data_name components size: %d\n", data_name->components_size);
  
  while (ri < rule->components_size && kni < key_name->components_size && dni < data_name->components_size) {

    printf("Value of ri, kni, dni: %d, %d, %d\n", ri, kni, dni);
    
    switch (rule->components[ri].type) {
    case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT:
      printf("In ndn_trust_schema_verify_key_name, found single name component.\n");
      if (memcmp(rule->components[ri].value, key_name->components[kni].value, rule->components[ri].size) != 0 ||
  	  rule->components[ri].size != key_name->components[kni].size) {
	printf("Found that key name was invalid.\n");
	printf("Value of rule->components[ri].value (size: %d):\n", rule->components[ri].size);
	for (int i = 0; i < rule->components[ri].size; i++) {
	  if (i > 0) printf(":");
	  printf("%02X", rule->components[ri].value[i]);
	}
	printf("\n");
	printf("Value of key_name->components[kni].value (size: %d):\n", key_name->components[kni].size);
	for (int i = 0; i < key_name->components[kni].size; i++) {
	  if (i > 0) printf(":");
	  printf("%02X", key_name->components[kni].value[i]);
	}
	printf("\n");
  	key_name_valid = false;
      }
      ri++;
      kni++;
      dni++;
      break;
    case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT:
      printf("In ndn_trust_Schema_verify_key_name, found wildcard name component.\n");
      ri++;
      kni++;
      dni++;
      break;
    case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE:
      printf("In ndn_trust_Schema_verify_key_name, found wildcard name component sequence.\n");
      break;
    }

    if (!key_name_valid)
      break;
  }

  return key_name_valid ? 0 : -1;
  
}
