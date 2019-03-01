
/*
 * Copyright (C) 2019 Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "trust-schema-tests.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#include "trust-schema-tests-def.h"
#include "../../riot-branch/ndn-riot-tests/test-helpers.h"
#include "../../riot-branch/ndn-riot-tests/print-helpers.h"

#include "../ndn-lite/encode/name.h"
#include "../ndn-lite/ndn-error-code.h"
#include "ndn-trust-schema.h"
#include "ndn-trust-schema-pattern-component.h"

#include "tiny-regex-c/re.h"

static const char *_current_test_name;

void _run_trust_schema_test(trust_schema_test_t *test);

bool run_trust_schema_tests(void) {
  memset(trust_schema_test_results, 0, sizeof(bool)*TRUST_SCHEMA_NUM_TESTS);
  for (int i = 0; i < TRUST_SCHEMA_NUM_TESTS; i++) {
    _run_trust_schema_test(&trust_schema_tests[i]);
  }
  
  return check_all_tests_passed(trust_schema_test_results, trust_schema_test_names,
                                TRUST_SCHEMA_NUM_TESTS);
}

void _run_trust_schema_test(trust_schema_test_t *test) {

  _current_test_name = test->test_names[test->test_name_index];
  
  int ret_val = -1;

  printf("Running trust schema test for following parameters:\n");
  printf("Rule data pattern: %.*s\n", test->rule_data_pattern_string_size, test->rule_data_pattern_string);
  printf("Rule key pattern: %.*s\n", test->rule_key_pattern_string_size, test->rule_key_pattern_string);
  printf("Data name: %.*s\n", test->data_name_string_size, test->data_name_string);
  printf("Key name: %.*s\n", test->key_name_string_size, test->key_name_string);
  
  ret_val = ndn_name_from_string(test->data_name, test->data_name_string, test->data_name_string_size);
  if (ret_val != NDN_SUCCESS) {
    print_error(_current_test_name, "_run_trust_schema_test", "ndn_name_from_string", ret_val);
    *test->passed = false;
    return;
  }
  
  ret_val = ndn_name_from_string(test->key_name, test->key_name_string, test->key_name_string_size);
  if (ret_val != NDN_SUCCESS) {
    print_error(_current_test_name, "_run_trust_schema_test", "ndn_name_from_string", ret_val);
    *test->passed = false;
    return;
  }
  
  ret_val = ndn_trust_schema_rule_from_strings(test->rule,
  					       test->rule_data_pattern_string, test->rule_data_pattern_string_size,
  					       test->rule_key_pattern_string, test->rule_key_pattern_string_size);
  if (ret_val != test->expected_rule_compilation_result) {
    printf("In %s, rule compilation result was %d; expected a rule compilation result of %d.\n", _current_test_name, ret_val, test->expected_rule_compilation_result);
    *test->passed = false;
    return;
  }
  if (test->expected_rule_compilation_result != NDN_SUCCESS) {
    *test->passed = true;
    return;
  }

  ret_val = ndn_trust_schema_verify_data_name_key_name_pair(test->rule, test->data_name, test->key_name);

  if ((ret_val == NDN_SUCCESS) != test->expected_match_result) {
    printf("In %s, match result was %d; expected a match result of %d.\n", _current_test_name, (ret_val == NDN_SUCCESS), test->expected_match_result);
    *test->passed = false;
    return;
  }
  
  *test->passed = true;
  
}
