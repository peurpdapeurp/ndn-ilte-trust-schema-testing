
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

int no_wildcard_sequence_match_data_name(const ndn_name_t *n, int nb, int ne, const ndn_trust_schema_pattern_t *p, int pb, int pe,
					 subpattern_idx *subpattern_idxs) {
  if (ne-nb != pe-pb)
    return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
  for (int i = 0; i < ne-nb; i++) {
    if (p->components[pb+i].type != NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT &&
	ndn_trust_schema_pattern_component_compare(&p->components[pb+i], &n->components[nb+i]) != 0)
      return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
    if (p->components[pb+i].subpattern_info >> 6 & NDN_TRUST_SCHEMA_SUBPATTERN_BEGIN_ONLY)
      subpattern_idxs[p->components[pb+i].subpattern_info & 0x3F].SPB_ni = nb+i;
    if (p->components[pb+i].subpattern_info >> 6 & NDN_TRUST_SCHEMA_SUBPATTERN_END_ONLY)
      subpattern_idxs[p->components[pb+i].subpattern_info & 0x3F].SPE_ni = nb+i;
  }
  return NDN_SUCCESS;
}

int no_wildcard_sequence_match_key_name(const ndn_name_t *n, int nb, int ne, const ndn_trust_schema_pattern_t *p, int pb, int pe) {
  if (ne-nb != pe-pb)
    return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
  for (int i = 0; i < ne-nb; i++) {
    if (p->components[pb+i].type != NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT &&
	ndn_trust_schema_pattern_component_compare(&p->components[pb+i], &n->components[nb+i]) != 0)
      return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
  }
  return NDN_SUCCESS;
}

int _index_of_data_name(const ndn_name_t *n, int nb, int ne, const ndn_trust_schema_pattern_t *p, int pb, int pe,
			subpattern_idx *subpattern_idxs) {
  for (int i = nb; i < ne; i++) {
    if (i+pe-pb <= ne &&
	no_wildcard_sequence_match_data_name(n, i, i+pe-pb, p, pb, pe, subpattern_idxs) == 0)
      return i;
  }
  return -1;
}

int _index_of_key_name(const ndn_name_t *n, int nb, int ne, const ndn_trust_schema_pattern_t *p, int pb, int pe) {
  for (int i = nb; i < ne; i++) {
    if (i+pe-pb <= ne &&
	no_wildcard_sequence_match_key_name(n, i, i+pe-pb, p, pb, pe) == 0)
      return i;
  }
  return -1;
}

int _check_data_name_against_pattern(const ndn_trust_schema_pattern_t *pattern, const ndn_name_t* name,
				     subpattern_idx *subpattern_idxs,
				     size_t num_subpattern_captures) {

  const char function_msg_prefix[] = "In _check_data_name_against_pattern,";

  printf("%s pattern's number of subpattern captures was: %d\n", function_msg_prefix, pattern->num_subpattern_captures);

  // allocate arrays for checking wildcard specializers
  char temp_wildcard_specializer_string_arr[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE];  
  char temp_name_component_string_arr[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE];

  if (pattern->components_size == 0 && name->components_size == 0) {
    return NDN_SUCCESS;
  }
  
  int pb = index_of_pattern_component_type(pattern, NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE);
  
  if (pb < 0) {
    return no_wildcard_sequence_match_data_name(name, 0, name->components_size, pattern, 0, pattern->components_size,
						subpattern_idxs);
  }

  int pe = last_index_of_pattern_component_type(pattern, NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE)+1;
  int nb = pb;
  int ne = name->components_size-(pattern->components_size-pe);
  
  if (nb > ne)
    return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
  if (no_wildcard_sequence_match_data_name(name, 0, nb, pattern, 0, pb, subpattern_idxs) != 0 ||
      no_wildcard_sequence_match_data_name(name, ne, name->components_size, pattern, pe, pattern->components_size, subpattern_idxs) != 0)
    return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;

  bool found_SPE = false;
  for (int i = pb; i < pe; i++) {
    while (i < pe && pattern->components[i].type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE) {
      i++;
      pb = i;
      if (pattern->components[i].subpattern_info >> 6 & NDN_TRUST_SCHEMA_SUBPATTERN_BEGIN_ONLY)
	subpattern_idxs[pattern->components[i].subpattern_info & 0x3F].SPB_ni = nb;
      if (pattern->components[i].subpattern_info >> 6 & NDN_TRUST_SCHEMA_SUBPATTERN_END_ONLY)
	found_SPE = true;
    }
    if (i == pe) {
      if (found_SPE)
	subpattern_idxs[pattern->components[pb].subpattern_info & 0x3F].SPE_ni = ne;
      return NDN_SUCCESS;
    }
    while (i < pe && pattern->components[i].type != NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE)
      i++;
    int j = _index_of_data_name(name, nb, ne, pattern, pb, i, subpattern_idxs);
    if (j == -1) {
      return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
    }
    if (found_SPE) {
      subpattern_idxs[pattern->components[pb].subpattern_info & 0x3F].SPE_ni = j;
      found_SPE = false;
    }
    nb = j+i-pb;
    pb = i+1;
  }
  return NDN_SUCCESS;
}

int _check_key_name_against_pattern(const ndn_trust_schema_pattern_t *pattern, const ndn_name_t* name,
				    const subpattern_idx *subpattern_idxs,
				    const ndn_name_t *subpattern_name,
				    size_t num_subpattern_captures) {

  const char function_msg_prefix[] = "In _check_key_name_against_pattern,";

  printf("%s pattern's number of subpattern captures was: %d\n", function_msg_prefix, pattern->num_subpattern_captures);

  // allocate arrays for checking wildcard specializers
  char temp_wildcard_specializer_string_arr[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE];  
  char temp_name_component_string_arr[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_STRING_MAX_SIZE];

  if (pattern->components_size == 0 && name->components_size == 0) {
    return NDN_SUCCESS;
  }
  
  int pb = index_of_pattern_component_type(pattern, NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE);
  
  if (pb < 0) {
    return no_wildcard_sequence_match_key_name(name, 0, name->components_size, pattern, 0, pattern->components_size);
  }

  int pe = last_index_of_pattern_component_type(pattern, NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE)+1;
  int nb = pb;
  int ne = name->components_size-(pattern->components_size-pe);
  
  if (nb > ne)
    return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
  if (no_wildcard_sequence_match_key_name(name, 0, nb, pattern, 0, pb) != 0 ||
      no_wildcard_sequence_match_key_name(name, ne, name->components_size, pattern, pe, pattern->components_size) != 0)
    return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;

  for (int i = pb; i < pe; i++) {
    while (i < pe && pattern->components[i].type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE) {
      i++;
      pb = i;
    }
    if (i == pe)
      return NDN_SUCCESS;
    while (i < pe && pattern->components[i].type != NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE)
      i++;
    int j = _index_of_key_name(name, nb, ne, pattern, pb, i);
    if (j == -1) {
      return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
    }
    nb = j+i-pb;
    pb = i+1;
  }
  return NDN_SUCCESS;
}

int
ndn_trust_schema_verify_data_name_key_name_pair(const ndn_trust_schema_rule_t* rule, const ndn_name_t* data_name, const ndn_name_t* key_name) {

  int ret_val = -1;
  
  const char function_msg_prefix[] = "In ndn_trust_schema_verify_key_name, ";

  printf("Checking data name pattern.\n\n");

  subpattern_idx data_name_subpattern_idxs[rule->data_pattern.num_subpattern_captures];
  ret_val = _check_data_name_against_pattern(&rule->data_pattern, data_name,
					data_name_subpattern_idxs, rule->data_pattern.num_subpattern_captures);
  if (ret_val != NDN_SUCCESS) {
    printf("%s failed to verify data name against rule's data pattern.\n", function_msg_prefix);
    return ret_val;
  }

  printf("After checking data name pattern, contents of subpattern index information of data name.\n");
  printf("Number of subpattern captures in data name: %d\n", rule->data_pattern.num_subpattern_captures);
  if (rule->data_pattern.num_subpattern_captures > 0) {
    for (int i = 0; i < rule->data_pattern.num_subpattern_captures; i++) {
      printf("Subpattern capture index %d indexes: begin index %d, end index %d\n",
	     i, data_name_subpattern_idxs[i].SPB_ni, data_name_subpattern_idxs[i].SPE_ni);
      printf("Subpattern capture name value: \n");
      for (int j = data_name_subpattern_idxs[i].SPB_ni; j < data_name_subpattern_idxs[i].SPE_ni+1; j++) {
	printf("/%.*s", data_name->components[j].size, data_name->components[j].value);
      }
      printf("\n");
    }
  }
  
  printf("Checking key name pattern.\n\n");
  
  ret_val = _check_key_name_against_pattern(&rule->key_pattern, key_name, data_name_subpattern_idxs,
					    data_name, rule->data_pattern.num_subpattern_captures);
  if (ret_val != NDN_SUCCESS) {
    printf("%s failed to verify key name against rule's key pattern.\n", function_msg_prefix);
    return ret_val;
  }

  return 0;
  
}
