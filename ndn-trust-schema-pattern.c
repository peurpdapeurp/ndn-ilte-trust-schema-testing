
#include "ndn-trust-schema-pattern.h"

#include <stdbool.h>
#include <stdio.h>

int
ndn_trust_schema_pattern_from_string(ndn_trust_schema_pattern_t* pattern, const char* string, uint32_t size) {

  printf("Converting this ndn trust schema pattern: %.*s\n", size, string);
  printf("---\n\n");
  
  int ret_val = -1;
  
  pattern->components_size = 0;
  
  // first check if it's a rule reference
  if (string[0] != '<' && string[0] != '(' && string[0] != '[' && string[0] != '\\') {
    ndn_trust_schema_pattern_component_t component;
    ret_val = ndn_trust_schema_pattern_component_from_string(&component, string, size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = ndn_trust_schema_pattern_append_component(pattern, &component);
    if (ret_val != NDN_SUCCESS) return ret_val;
    return 0;
  }

  // flag to remember whether the pattern component being appended should be marked as the beginning of a subpattern (SPB = Sub Pattern Beginning)
  bool should_add_SPB = false;
  // current subpattern index; will return error if more than NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES subpatterns are found
  uint8_t current_subpattern_begin_index = 0;
  uint8_t current_subpattern_end_index = 0;
  const char * current_string = string;
  // iterate through the schema pattern
  while (current_string - string < size) {

    printf("Value of current string - string in current while loop iteration: %zd\n", current_string - string);
    
    int pattern_comp_end_index = -1;

    switch (current_string[0]) {
    case '<':
      pattern_comp_end_index = re_match("^<>\\*", current_string);
      if (pattern_comp_end_index == TINY_REGEX_C_FAIL) {
	pattern_comp_end_index = re_match(">", current_string);
	if (pattern_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
      }
      else {
	pattern_comp_end_index += 2;
      }
      break;
    case '[':
      pattern_comp_end_index = re_match("]", current_string);
      if (pattern_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
      break;
    case '\\':
      printf("Found a \\ character in pattern being parsed.\n");
      pattern_comp_end_index = re_match("[0-9]", current_string);
      if (pattern_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
      break;
    case '(':
      printf("Found (, setting should_add_SPB flag.\n");
      // make sure that there is a corresponding end parentheses for this subpattern
      pattern_comp_end_index = re_match(")", current_string);
      if (pattern_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
      should_add_SPB = true;
      current_string += 1;
      continue;
    case ')':
      printf ("Found ), setting previous pattern component's subpattern info accordingly.\n");
      // set the last pattern component's subpattern info to indicate that it was the ending of a subpattern
      pattern->components[pattern->components_size - 1].subpattern_info |=
	(NDN_TRUST_SCHEMA_SUBPATTERN_END_ONLY << 6) | (current_subpattern_end_index);
      current_subpattern_end_index++;
      printf("Found ), value of previous pattern components subpattern info: %d\n", pattern->components[pattern->components_size - 1].subpattern_info);
      current_string += 1;
      continue;
    default:
      if (current_string[0] == '\0')
	break;
      else
	return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
    }

    int pattern_comp_string_len = pattern_comp_end_index + 1;

    ndn_trust_schema_pattern_component_t component;
    component.subpattern_info = 0;
    ret_val = ndn_trust_schema_pattern_component_from_string(&component, current_string, pattern_comp_string_len);
    if (ret_val != NDN_SUCCESS) return ret_val;

    if (should_add_SPB) {
      printf("Found that should_add_SPB flag was set when appending a component, setting subpattern_info field of component being appended accordingly...\n");	    
      // set the current pattern component's subpattern info to indicate that it was the beginning of a subpattern
      component.subpattern_info |=
	(NDN_TRUST_SCHEMA_SUBPATTERN_BEGIN_ONLY << 6) | (current_subpattern_begin_index << 3);
      current_subpattern_begin_index++;
      printf("Found (, value of current pattern components subpattern info: %d\n", pattern->components[pattern->components_size].subpattern_info);
      if (current_subpattern_begin_index + 1 > NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES) {
	return NDN_TRUST_SCHEMA_NUMBER_OF_SUBPATTERNS_EXCEEDS_LIMIT;
      }
      should_add_SPB = false;
      printf("Value of subpattern_info of pattern component being appended: %d\n", component.subpattern_info);	
    }
    
    ret_val = ndn_trust_schema_pattern_append_component(pattern, &component);
    if (ret_val != NDN_SUCCESS) return ret_val;

    current_string += pattern_comp_end_index + 1;

  }

  printf("After while loop...\n");

  printf("Value of all subpattern infos for entire pattern: \n");
  for (int i = 0; i < pattern->components_size; i++) {
    printf("Type of pattern component %d: %d\n", i, pattern->components[i].type);
    printf("Subpattern info of pattern component %d: %d\n", i, pattern->components[i].subpattern_info);
  }

  if (current_subpattern_begin_index != current_subpattern_end_index) {
    return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
  }

  pattern->num_subpattern_captures = current_subpattern_begin_index;
  
  return 0;
  
}

int
index_of_pattern_component_type(const ndn_trust_schema_pattern_t* pattern, int type) {

  if (pattern->components_size == 0)
    return -1;

  for (int i = 0; i < pattern->components_size; i++) {
    if (pattern->components[i].type == type)
      return i;
  }

  return -1;
  
}

int
last_index_of_pattern_component_type(const ndn_trust_schema_pattern_t* pattern, int type) {

  if (pattern->components_size == 0)
    return -1;

  for (int i = pattern->components_size-1; i >= 0; i--) {
    if (pattern->components[i].type == type)
      return i;
  }

  return -1;
  
}
