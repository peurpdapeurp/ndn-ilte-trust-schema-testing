
#include "ndn-trust-schema.h"

#include "../ndn-lite/ndn-error-code.h"
#include "../ndn-lite/ndn-constants.h"

#include <stdbool.h>
#include <stdio.h>

void _check_name_against_pattern(bool *name_valid, const ndn_trust_schema_pattern_t *pattern, const ndn_name_t* name) {

  /* printf("Values in pattern: \n"); */
  /* for (int i = 0; i < pattern->components_size; i++) { */
  /*   printf("Type of pattern index %d: %d\n", i, pattern->components[i].type); */
  /*   switch (pattern->components[i].type) { */
  /*   case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT:   */
  /*     printf("  Value of pattern index %d: %.*s\n", i, pattern->components[i].size, pattern->components[i].value); */
  /*   default: */
  /*     break; */
  /*   } */
  /* } */

  /* printf("Values in name: \n"); */
  /* for (int i = 0; i < name->components_size; i++) { */
  /*   printf("Value of name index %d: %.*s\n", i, name->components[i].size, name->components[i].value); */
  /* } */

  /* printf("\n\n"); */
  
  /* int pi = 0, ni = 0; */
  
  /* while (pi < pattern->components_size && ni < name->components_size) {     */
  /*   switch (pattern->components[pi].type) { */
  /*   case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT:       */
  /*     if (memcmp(pattern->components[pi].value, name->components[ni].value, pattern->components[pi].size) != 0 || */
  /* 	  pattern->components[pi].size != name->components[ni].size) { */
  /* 	*name_valid = false; */
  /*     } */
  /*     pi++; */
  /*     ni++; */
  /*     break; */
  /*   case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT: */
  /*     pi++; */
  /*     ni++; */
  /*     break; */
  /*   case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE: */
      
  /*     break; */
  /*   } */

  /*   if (!(*name_valid)) */
  /*     break; */
  /* } */

  int pat_len = pattern->components_size;
  int name_len = name->components_size;
  
  if (pat_len == 0 && name_len == 0) {
    *name_valid = true;
    return;
  }

  bool results[name_len+1][pat_len+1];

  // initialize all results to false
  for (int i = 0; i < name_len+1; i++) {
    for (int j = 0; j < pat_len+1; j++) {
      results[i][j] = false;
    }
  }

  printf("Value of results array after initialization:\n");
  for (int i = 0; i < name_len; i++) {
    for (int j = 0; j < pat_len; j++) {
      printf("%d ", results[i][j]);
    }
    printf("\n");
  }
  printf("\n\n");
  
  // for the base case of comparing an empty string to an empty pattern,
  // the result is true
  results[0][0] = true;

  // first check successively larger substrings of the schema pattern containing
  // the first character of the pattern (i.e. from pattern "abc", check "a", then "ab", then "abc")
  // against an empty string
  for (int j = 1; j < pat_len+1; j++) {
    if (pattern->components[j-1].type != NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE)
      break;
    results[0][j] = true;
  }

  for (int i = 1; i < name_len+1; i++) {
    for (int j = 1; j < pat_len+1; j++) {
      if (pattern->components[j-1].type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT ||
	  
	  (pattern->components[j-1].type == NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT &&
	   memcmp(pattern->components[j-1].value, name->components[i-1].value, pattern->components[j-1].size) == 0 &&
	   pattern->components[j-1].size == name->components[i-1].size)
	  
	  )
      {
        results[i][j] = results[i-1][j-1];
      }
      else if (pattern->components[j-1].type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE) {
        results[i][j] = (results[i-1][j] || results[i][j-1]);
      }
    }
  }

  printf("Value of results array after processing:\n");
  for (int i = 0; i < name_len+1; i++) {
    for (int j = 0; j < pat_len+1; j++) {
      printf("%d ", results[i][j]);
    }
    printf("\n");
  }
  printf("\n\n");
  
  *name_valid = results[name_len][pat_len];
}

int
ndn_trust_schema_verify_data_name_key_name_pair(const ndn_trust_schema_rule_t* rule, const ndn_name_t* data_name, const ndn_name_t* key_name) {

  const char function_msg_prefix[] = "In ndn_trust_schema_verify_key_name, ";
  
  bool data_name_valid = true;
  bool key_name_valid = true;

  printf("Checking data name pattern.\n\n");
  
  _check_name_against_pattern(&data_name_valid, &rule->data_pattern, data_name);

  printf("Checking key name pattern.\n\n");
  
  _check_name_against_pattern(&key_name_valid, &rule->key_pattern, key_name);
  
  return (data_name_valid && key_name_valid) ? 0 : -1;
  
}
