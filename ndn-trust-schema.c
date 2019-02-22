
#include "ndn-trust-schema.h"

#include "../ndn-lite/ndn-error-code.h"
#include "../ndn-lite/ndn-constants.h"

#include <stdbool.h>
#include <stdio.h>

typedef struct {
  // the subpattern pattern end index
  int SPE_pi;
  // the subpattern pattern begin index
  int SPE_ni;
  // the subpattern's associated name end index
  int SPB_pi;
  // the subpattern's associated name begin index
  int SPB_ni;
} subpattern_index_info;

int _check_name_against_pattern(const ndn_trust_schema_pattern_t *pattern, const ndn_name_t* name,
				subpattern_index_info *subpattern_index_infos,
				size_t num_subpattern_captures,
				const ndn_name_t* prev_name,
				const subpattern_index_info* prev_subpattern_index_infos,
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

  bool results[name_len+1][pat_len+1];

  // initialize all results to false
  for (int i = 0; i < name_len+1; i++) {
    for (int j = 0; j < pat_len+1; j++) {
      results[i][j] = false;
    }
  }

  // for the base case of comparing a 0 component name to a 0 component pattern,
  // the result is true
  results[0][0] = true;
  
  // first check successively larger substrings of the schema pattern containing
  // the first component of the pattern (i.e. from pattern <a><b><c>, check <a>, then <ab>, then <abc>)
  // against a 0 component name
  for (int j = 1; j < pat_len+1; j++) {
    if (pattern->components[j].type != NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE &&
	pattern->components[j].type != NDN_TRUST_SCHEMA_SUBPATTERN_INDEX)
      break;
    results[0][j] = true;
  }

  for (int i = 1; i < name_len+1; i++) {
    for (int j = 1; j < pat_len+1; j++) {
      
      if (pattern->components[j].type == NDN_TRUST_SCHEMA_PADDING_COMPONENT) {
	results[i][j] = results[i-1][j-1];
      }
      else if (pattern->components[j].type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT)
      {
        results[i][j] = results[i-1][j-1];
      }
      else if (pattern->components[j].type == NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT) {
	if (
	    memcmp(pattern->components[j].value, name->components[i-1].value, pattern->components[j].size) == 0 &&
	    pattern->components[j].size == name->components[i-1].size
	    ) {
	  results[i][j] = results[i-1][j-1];
	}
      }
      else if (pattern->components[j].type == NDN_TRUST_SCHEMA_WILDCARD_SPECIALIZER) {
	memcpy(temp_wildcard_specializer_string_arr, pattern->components[j].value, pattern->components[j].size);
	temp_wildcard_specializer_string_arr[pattern->components[j].size] = '\0';

	memcpy(temp_name_component_string_arr, name->components[i-1].value, name->components[i-1].size);
	temp_name_component_string_arr[name->components[i-1].size] = '\0';
	
	int ret_val = re_match(temp_wildcard_specializer_string_arr, temp_name_component_string_arr);
	if (ret_val != TINY_REGEX_C_FAIL) {
	  results[i][j] = results[i-1][j-1];
	}
      }
      else if (pattern->components[j].type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE) {
        results[i][j] = (results[i-1][j] || results[i][j-1]);
      }
      else if (pattern->components[j].type == NDN_TRUST_SCHEMA_SUBPATTERN_INDEX) {
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

  if  (!results[name_len][pat_len]) {
    return NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH;
  }

  if (num_subpattern_captures == 0)
    return NDN_SUCCESS;


  // if subpattern_index_infos is not NULL, this means that this call to _check_name_against_pattern is the beginning of
  // a chain of verifications; it will populate the subpattern_index_infos array it was passed with the subpattern matches
  // of the current data name
  if (subpattern_index_infos != NULL) {
    int name_index = name_len;
    int pattern_index = pattern->components_size-1;
    int last_pattern_index = pattern_index;
    int current_subpattern_info = 0;
    int current_subpattern_info_type = 0;
    int subpattern_index = 0;
    
    // first check the dummy component at the end of the pattern to see if it is the end of a subpattern
    current_subpattern_info = pattern->components[pattern_index].subpattern_info;
    current_subpattern_info_type = current_subpattern_info >> 6;
    if (current_subpattern_info_type & NDN_TRUST_SCHEMA_SUBPATTERN_END_ONLY) {
      printf("Dummy component at end of pattern was a subpattern ending.\n");
      subpattern_index = current_subpattern_info & 0x07;
      printf("Index of subpattern ending: %d\n", subpattern_index);
      subpattern_index_infos[subpattern_index].SPE_pi = pattern_index-1;
      subpattern_index_infos[subpattern_index].SPE_ni = name_index;
    }
    
    pattern_index--;
    
    printf("--\n");
    
    while (name_index >= 0 && pattern_index >= 0) {
      
      // check to see if we have changed columns since the last iteration; this will allow us
      // to properly populate subpattern index ending's name indexes
      if (pattern_index != last_pattern_index) {
	
	printf("Got to a new pattern index of %d\n", pattern_index);
	
	for (int i = 0; i < num_subpattern_captures; i++) {
	  if (subpattern_index_infos[i].SPE_pi == pattern_index) {
	    
	    printf("Found that subpattern index %d's SPE_pi was equal to %d; setting its SPE_ni to %d.\n",
		   i, pattern_index, name_index);
	    
	    subpattern_index_infos[i].SPE_ni = name_index;
	  }
	}
	
	last_pattern_index = pattern_index;
      }
      
      // check the subpattern info of the current step, to see if there is any subpattern ending or beginning
      // index information stored here
      current_subpattern_info = pattern->components[pattern_index].subpattern_info;
      current_subpattern_info_type = current_subpattern_info >> 6;
      if ((pattern->components[pattern_index].subpattern_info >> 6) & NDN_TRUST_SCHEMA_SUBPATTERN_BEGIN_ONLY) {
	printf("At pattern index %d and name index %d, found a subpattern beginning.\n", pattern_index, name_index);
	subpattern_index = (pattern->components[pattern_index].subpattern_info >> 3) & 0x07;
	printf("Index of subpattern beginning: %d\n", subpattern_index);
	subpattern_index_infos[subpattern_index].SPB_pi = pattern_index;
	subpattern_index_infos[subpattern_index].SPB_ni = name_index;
      }
      if ((pattern->components[pattern_index].subpattern_info >> 6) & NDN_TRUST_SCHEMA_SUBPATTERN_END_ONLY) {
	printf("At pattern index %d and name index %d, found a subpattern ending.\n", pattern_index, name_index);
	subpattern_index = (pattern->components[pattern_index].subpattern_info) & 0x07;
	printf("Index of subpattern ending: %d\n", subpattern_index);
	subpattern_index_infos[subpattern_index].SPE_pi = pattern_index-1;
      }
      if ((pattern->components[pattern_index].subpattern_info >> 6) == 0) {
	printf("At pattern index %d and name index %d, found a pattern that was netiher beginning or ending of subpattern.\n",
	       pattern_index, name_index);
      }
      
      // now check the type of the pattern compoennt to see what the indexes of the previous submatch were
      // (i.e., what indexes of the results table we should backtrace to)
      if (pattern->components[pattern_index].type == NDN_TRUST_SCHEMA_PADDING_COMPONENT) {
	printf("Got to a pattern padding component (pattern index %d), meaning we have reached the beginning of the pattern.\n", pattern_index);
	break;
      }
      else if (pattern->components[pattern_index].type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT) {
	printf("Got to a wildcard name component (pattern index %d), meaning the previous match was at the diagonal upper left.\n", pattern_index);
	pattern_index--;
	name_index--;
      }
      else if (pattern->components[pattern_index].type == NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT) {
	printf("Got to a single name component (pattern index %d), meaning the previous match was at the diagonal upper left.\n", pattern_index);
	pattern_index--;
	name_index--;
      }
      else if (pattern->components[pattern_index].type == NDN_TRUST_SCHEMA_WILDCARD_SPECIALIZER) {
	printf("Got to a wildcard specializer (pattern index %d), meaning the previous match was at the diagonal upper left.\n", pattern_index);
	pattern_index--;
	name_index--;
      }
      else if (pattern->components[pattern_index].type == NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE) {
	printf("Got to a wildcard name component sequence (pattern index %d).\n", pattern_index);
	if (results[name_index-1][pattern_index]) {
	  printf("Found by checking the results table that the wildcard name component sequence's last step was above.\n");
	  name_index--;
	}
	else if (results[name_index][pattern_index-1]) {
	  printf("Found by checking the results table that the wildcard name component sequence's last step was to the left.\n");
	  pattern_index--;
	}
      }
      
      printf("--\n");
      
    }
    printf("\n\n");
    
  }
  // if subpattern_index_infos was NULL, it is assumed that prev_subpattern_index_infos was not null, in which case this call
  // to _check_name_against_pattern is in the middle or end of a verification chain; it will use the previous data name and
  // the indexes of the prev_subpattern_index_infos array to populate the subpattern matches of the current data name with
  // the subpattern matches of the previous data name with the same index (i.e, the first subpattern match of the previous
  // data name will be mapped to the first subpattern match of the current data name, and be used to check for a match)
  else {

    printf("In _check_name_against_pattern, was passed a reference to a previous data name and the subpattern index info for that data name; printing that now.\n\n");

    int SPE_pi, SPB_pi, SPE_ni, SPB_ni;
    printf("Subpattern index information:\n-----\n");
    for (int i = 0; i < prev_num_subpattern_captures; i++) {
      
      printf("Information of subpattern index %d:\n", i);
      
      SPE_ni = prev_subpattern_index_infos[i].SPE_ni;
      SPB_ni = prev_subpattern_index_infos[i].SPB_ni;
      
      printf("SPE_ni: %d\n", SPE_ni);    
      printf("SPB_ni: %d\n", SPB_ni);
      
      printf("Value of name for subpattern match, calculated using _ni indexes:\n");    
      for (int i = 0; i < SPE_ni - SPB_ni; i++) {
	int current_name_index = SPB_ni + i;
	printf("/%.*s", name->components[current_name_index].size, name->components[current_name_index].value);
      }
      printf("\n\n");
      
      printf("--\n");
    }
    printf("\n");
    
  }
  
  return NDN_SUCCESS;
}

int
ndn_trust_schema_verify_data_name_key_name_pair(const ndn_trust_schema_rule_t* rule, const ndn_name_t* data_name, const ndn_name_t* key_name) {

  int ret_val = -1;
  
  const char function_msg_prefix[] = "In ndn_trust_schema_verify_key_name, ";

  printf("Checking data name pattern.\n\n");

  subpattern_index_info data_name_subpattern_index_infos[rule->data_pattern.num_subpattern_captures];
  ret_val = _check_name_against_pattern(&rule->data_pattern, data_name,
					data_name_subpattern_index_infos, rule->data_pattern.num_subpattern_captures,
					NULL, NULL, -1);
  if (ret_val != NDN_SUCCESS) {
    printf("%s failed to verify data name against rule's data pattern.\n", function_msg_prefix);
    return ret_val;
  }

  printf("Checking key name pattern.\n\n");
  
  ret_val = _check_name_against_pattern(&rule->key_pattern, key_name,
					NULL, -1,
					data_name, data_name_subpattern_index_infos, rule->data_pattern.num_subpattern_captures);
  if (ret_val != NDN_SUCCESS) {
    printf("%s failed to verify key name against rule's key pattern.\n", function_msg_prefix);
    return ret_val;
  }

  return 0;
  
}
