
/*
 * Copyright (C) 2019 Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "trust-schema-tests-def.h"

#include "../ndn-lite/ndn-enums.h"

char *trust_schema_test_names[TRUST_SCHEMA_NUM_TESTS] = {
  "test_trust_schema_1",
};

bool trust_schema_test_results[TRUST_SCHEMA_NUM_TESTS];


trust_schema_test_t trust_schema_tests[TRUST_SCHEMA_NUM_TESTS] = {
    {
      trust_schema_test_names,
      0,
      &test_rule_1,
      test_rule_1_data_pattern_string,
      strlen(test_rule_1_data_pattern_string),
      test_rule_1_key_pattern_string,
      strlen(test_rule_1_key_pattern_string),
      &test_data_name_1,
      test_data_name_1_string,
      strlen(test_data_name_1_string),
      &test_key_name_1,
      test_key_name_1_string,
      strlen(test_key_name_1_string),
      &trust_schema_test_results[0]
    },
};

ndn_trust_schema_rule_t test_rule_1;

ndn_name_t test_data_name_1;

ndn_name_t test_key_name_1;
