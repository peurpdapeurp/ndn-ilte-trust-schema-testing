
#include "ndn-trust-schema-pattern.h"

#include <stdbool.h>
#include <stdio.h>

int
ndn_trust_schema_pattern_from_string(ndn_trust_schema_pattern_t* pattern, const char* string, uint32_t size) {

  printf("Converting this ndn trust schema pattern: %.*s\n", size, string);
  printf("---\n\n");
  
  int ret_val = -1;
  
  pattern->components_size = 0;

  // add a padding pattern component, in case the pattern begins with a subpattern capture group
  ndn_trust_schema_pattern_component_t beginning_padding_component;
  beginning_padding_component.type = NDN_TRUST_SCHEMA_PADDING_COMPONENT;
  beginning_padding_component.subpattern_info = 0;
  ret_val = ndn_trust_schema_pattern_append_component(pattern, &beginning_padding_component);
  if (ret_val != NDN_SUCCESS) return ret_val;
  
  // first check if it's a rule reference
  if (string[0] != '<' && string[0] != '(' && string[0] != '[' && string[0] != '\\') {
    ndn_trust_schema_pattern_component_t component;
    ret_val = ndn_trust_schema_pattern_component_from_string(&component, string, size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = ndn_trust_schema_pattern_append_component(pattern, &component);
    if (ret_val != NDN_SUCCESS) return ret_val;
    return 0;
  }

  // flag to remember whether the next pattern component appended should be marked as the end of a subpattern (SPE = Sub Pattern End)
  bool should_add_SPE = false;
  // current subpattern index; will return error if more than NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES subpatterns are found
  uint8_t current_subpattern_begin_index = 0;
  uint8_t current_subpattern_end_index = 0;
  const char * current_string = string;
  // iterate through the schema pattern
  while (current_string - string < size) {

    printf("Value of string - current string in current while loop iteration: %zd\n", current_string - string);
    
    int pattern_comp_end_index = -1;
    
    if (current_string[0] == '<') {
      pattern_comp_end_index = re_match("^<>\\*", current_string);
      if (pattern_comp_end_index == TINY_REGEX_C_FAIL) {
	pattern_comp_end_index = re_match(">", current_string);
	if (pattern_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
      }
      else {
	pattern_comp_end_index += 2;
      }
    }
    else if (current_string[0] == '[') {
      pattern_comp_end_index = re_match("]", current_string);
      if (pattern_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
    }
    else if (current_string[0] == '\\') {
      printf("Found a \\ character in pattern being parsed.\n");
      pattern_comp_end_index = re_match("[0-9]", current_string);
      if (pattern_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
    }
    else if (current_string[0] == '(') {
      // make sure that there is a corresponding end parentheses for this subpattern
      pattern_comp_end_index = re_match(")", current_string);
      if (pattern_comp_end_index == TINY_REGEX_C_FAIL) return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR;
      // set the previous pattern component's subpattern info to indicate that it was the beginning of a subpattern
      pattern->components[pattern->components_size - 1].subpattern_info |=
	(NDN_TRUST_SCHEMA_SUBPATTERN_BEGIN_ONLY << 6) | (current_subpattern_begin_index << 3);
      current_subpattern_begin_index ++;
      printf("Found (, value of previous pattern components subpattern info: %d\n", pattern->components[pattern->components_size - 1].subpattern_info);
      if (current_subpattern_begin_index + 1 > NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES) {
	return NDN_TRUST_SCHEMA_NUMBER_OF_SUBPATTERNS_EXCEEDS_LIMIT;
      }
      current_string += 1;
      continue;
    }
    else if (current_string[0] == ')') {
      printf ("Found ), setting should_add_SPE flag.\n");
      // set the flag that indicates that the next component appended should be marked as an SPE (Sub Pattern End)
      should_add_SPE = true;
      current_string += 1;
      continue;
    }
    else {
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

    if (should_add_SPE) {
      printf("Found that should_add_SPE flag was set when appending a component, setting subpattern_info field of component being appended accordingly...\n");
      should_add_SPE = false;
      component.subpattern_info |=
	(NDN_TRUST_SCHEMA_SUBPATTERN_END_ONLY << 6) | (current_subpattern_end_index);
      current_subpattern_end_index++;
      printf("Value of subpattern_info of pattern component being appended: %d\n", component.subpattern_info);	
    }
    
    ret_val = ndn_trust_schema_pattern_append_component(pattern, &component);
    if (ret_val != NDN_SUCCESS) return ret_val;

    current_string += pattern_comp_end_index + 1;

  }

  printf("After while loop...\n");
  
  printf("After while loop, value of should_add_SPE flag: %d\n", should_add_SPE);
  
  // add a padding pattern component, in case the pattern ends with a subpattern capture group
  ndn_trust_schema_pattern_component_t ending_padding_component;
  ending_padding_component.type = NDN_TRUST_SCHEMA_PADDING_COMPONENT;
  ending_padding_component.subpattern_info = 0;
  
  if (should_add_SPE) {
    printf("Found that should_add_SPE flag was set when appending final padding component, setting subpattern_info field of component being appended accordingly...\n");
    should_add_SPE = false;
    ending_padding_component.subpattern_info |=
      (NDN_TRUST_SCHEMA_SUBPATTERN_END_ONLY << 6) | (current_subpattern_end_index);
    current_subpattern_end_index++;
    printf("Value of subpattern_info of pattern component being appended: %d\n", ending_padding_component.subpattern_info);	
  }  
  
  ret_val = ndn_trust_schema_pattern_append_component(pattern, &ending_padding_component);
  if (ret_val != NDN_SUCCESS) return ret_val;

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
