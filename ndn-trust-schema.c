
#include "ndn-trust-schema.h"

#include "../ndn-lite/ndn-error-code.h"
#include "../ndn-lite/ndn-constants.h"

#include <stdbool.h>
#include <stdio.h>

typedef struct {
  // the subpattern's associated name end index
  int SPE_ni;
  // the subpattern's associated name begin index
  int SPB_ni;
} subpattern_idx;

typedef struct {
  // the non-<>*-pattern-component subsequence's beginning pattern index
  int NSSB_pi;
  // the non-<>*-pattern-component subsequence's ending pattern index
  int NSSE_pi;
} non_star_sub_seq_idx;

int _check_name_against_pattern(const ndn_trust_schema_pattern_t *pattern, const ndn_name_t* name,
				subpattern_idx *subpattern_idxs,
				size_t num_subpattern_captures,
				const ndn_name_t* prev_name,
				const subpattern_idx* prev_subpattern_idxs,
				size_t prev_num_subpattern_captures) {

  const char function_msg_prefix[] = "In _check_name_against_pattern,";

  printf("%s pattern's number of subpattern captures was: %d\n", function_msg_prefix, pattern->num_subpattern_captures);
  
  if (pattern->components_size < 2) {
    return NDN_TRUST_SCHEMA_PATTERN_TOO_SMALL;
  }
  if (pattern->components[0].type != NDN_TRUST_SCHEMA_PADDING_COMPONENT) {
    return NDN_TRUST_SCHEMA_PATTERN_DID_NOT_START_WITH_PADDING_COMPONENT;
  }
  if (pattern->components[pattern->components_size-1].type != NDN_TRUST_SCHEMA_PADDING_COMPONENT) {
    return NDN_TRUST_SCHEMA_PATTERN_DID_NOT_END_WITH_PADDING_COMPONENT;
  }

  // allocate arrays for checking wildcard specializers
  char temp_wildcard_specializer_string_arr[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE];  
  char temp_name_component_string_arr[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE];

  // subtract two to account for the end and beginning padding components, which are only there to
  // store subpattern indexing related information for subpatterns at the beginning / end of pattern
  int pat_len = pattern->components_size - 2;
  int name_len = name->components_size;

  
  
  if (pat_len == 2 && name_len == 0) {
    return NDN_SUCCESS;
  }

}

int
ndn_trust_schema_verify_data_name_key_name_pair(const ndn_trust_schema_rule_t* rule, const ndn_name_t* data_name, const ndn_name_t* key_name) {

  int ret_val = -1;
  
  const char function_msg_prefix[] = "In ndn_trust_schema_verify_key_name, ";

  printf("Checking data name pattern.\n\n");

  subpattern_idx data_name_subpattern_idxs[rule->data_pattern.num_subpattern_captures];
  ret_val = _check_name_against_pattern(&rule->data_pattern, data_name,
					data_name_subpattern_idxs, rule->data_pattern.num_subpattern_captures,
					NULL, NULL, -1);
  if (ret_val != NDN_SUCCESS) {
    printf("%s failed to verify data name against rule's data pattern.\n", function_msg_prefix);
    return ret_val;
  }

  printf("Checking key name pattern.\n\n");
  
  ret_val = _check_name_against_pattern(&rule->key_pattern, key_name,
					NULL, -1,
					data_name, data_name_subpattern_idxs, rule->data_pattern.num_subpattern_captures);
  if (ret_val != NDN_SUCCESS) {
    printf("%s failed to verify key name against rule's key pattern.\n", function_msg_prefix);
    return ret_val;
  }

  return 0;
  
}
