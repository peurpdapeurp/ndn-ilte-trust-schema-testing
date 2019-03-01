

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
  "test_trust_schema_pattern_left_wildcards_match",
  "test_trust_schema_pattern_left_wildcards_mismatch",
  "test_trust_schema_pattern_right_wildcards_match",
  "test_trust_schema_pattern_right_wildcards_mismatch",
  "test_trust_schema_pattern_surrounded_wildcards_match",
  "test_trust_schema_pattern_surrounded_wildcards_mismatch",
  "test_trust_schema_pattern_no_wildcards_match",
  "test_trust_schema_pattern_no_wildcards_mismatch",
  "test_trust_schema_pattern_only_wildcards_match",
  "test_trust_schema_pattern_wildcard_specializer_match",
  "test_trust_schema_pattern_wildcard_specializer_mismatch",
  "test_trust_schema_pattern_invalid_format_multiple_consecutive_wildcard_sequences",
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
      expected_rule_compilation_return_1,
      expected_match_1,
      &trust_schema_test_results[0]
    },
    {
      trust_schema_test_names,
      1,
      &test_rule_2,
      test_rule_2_data_pattern_string,
      strlen(test_rule_2_data_pattern_string),
      test_rule_2_key_pattern_string,
      strlen(test_rule_2_key_pattern_string),
      &test_data_name_2,
      test_data_name_2_string,
      strlen(test_data_name_2_string),
      &test_key_name_2,
      test_key_name_2_string,
      strlen(test_key_name_2_string),
      expected_rule_compilation_return_2,
      expected_match_2,
      &trust_schema_test_results[1]
    },
    {
      trust_schema_test_names,
      2,
      &test_rule_3,
      test_rule_3_data_pattern_string,
      strlen(test_rule_3_data_pattern_string),
      test_rule_3_key_pattern_string,
      strlen(test_rule_3_key_pattern_string),
      &test_data_name_3,
      test_data_name_3_string,
      strlen(test_data_name_3_string),
      &test_key_name_3,
      test_key_name_3_string,
      strlen(test_key_name_3_string),
      expected_rule_compilation_return_3,
      expected_match_3,
      &trust_schema_test_results[2]
    },
    {
      trust_schema_test_names,
      3,
      &test_rule_4,
      test_rule_4_data_pattern_string,
      strlen(test_rule_4_data_pattern_string),
      test_rule_4_key_pattern_string,
      strlen(test_rule_4_key_pattern_string),
      &test_data_name_4,
      test_data_name_4_string,
      strlen(test_data_name_4_string),
      &test_key_name_4,
      test_key_name_4_string,
      strlen(test_key_name_4_string),
      expected_rule_compilation_return_4,
      expected_match_4,
      &trust_schema_test_results[3]
    },
    {
      trust_schema_test_names,
      4,
      &test_rule_5,
      test_rule_5_data_pattern_string,
      strlen(test_rule_5_data_pattern_string),
      test_rule_5_key_pattern_string,
      strlen(test_rule_5_key_pattern_string),
      &test_data_name_5,
      test_data_name_5_string,
      strlen(test_data_name_5_string),
      &test_key_name_5,
      test_key_name_5_string,
      strlen(test_key_name_5_string),
      expected_rule_compilation_return_5,
      expected_match_5,
      &trust_schema_test_results[4]
    },
    {
      trust_schema_test_names,
      5,
      &test_rule_6,
      test_rule_6_data_pattern_string,
      strlen(test_rule_6_data_pattern_string),
      test_rule_6_key_pattern_string,
      strlen(test_rule_6_key_pattern_string),
      &test_data_name_6,
      test_data_name_6_string,
      strlen(test_data_name_6_string),
      &test_key_name_6,
      test_key_name_6_string,
      strlen(test_key_name_6_string),
      expected_rule_compilation_return_6,
      expected_match_6,
      &trust_schema_test_results[5]
    },
    {
      trust_schema_test_names,
      6,
      &test_rule_7,
      test_rule_7_data_pattern_string,
      strlen(test_rule_7_data_pattern_string),
      test_rule_7_key_pattern_string,
      strlen(test_rule_7_key_pattern_string),
      &test_data_name_7,
      test_data_name_7_string,
      strlen(test_data_name_7_string),
      &test_key_name_7,
      test_key_name_7_string,
      strlen(test_key_name_7_string),
      expected_rule_compilation_return_7,
      expected_match_7,
      &trust_schema_test_results[6]
    },
    {
      trust_schema_test_names,
      7,
      &test_rule_8,
      test_rule_8_data_pattern_string,
      strlen(test_rule_8_data_pattern_string),
      test_rule_8_key_pattern_string,
      strlen(test_rule_8_key_pattern_string),
      &test_data_name_8,
      test_data_name_8_string,
      strlen(test_data_name_8_string),
      &test_key_name_8,
      test_key_name_8_string,
      strlen(test_key_name_8_string),
      expected_rule_compilation_return_8,
      expected_match_8,
      &trust_schema_test_results[7]
    },
    {
      trust_schema_test_names,
      8,
      &test_rule_9,
      test_rule_9_data_pattern_string,
      strlen(test_rule_9_data_pattern_string),
      test_rule_9_key_pattern_string,
      strlen(test_rule_9_key_pattern_string),
      &test_data_name_9,
      test_data_name_9_string,
      strlen(test_data_name_9_string),
      &test_key_name_9,
      test_key_name_9_string,
      strlen(test_key_name_9_string),
      expected_rule_compilation_return_9,
      expected_match_9,
      &trust_schema_test_results[8]
    },
    {
      trust_schema_test_names,
      9,
      &test_rule_10,
      test_rule_10_data_pattern_string,
      strlen(test_rule_10_data_pattern_string),
      test_rule_10_key_pattern_string,
      strlen(test_rule_10_key_pattern_string),
      &test_data_name_10,
      test_data_name_10_string,
      strlen(test_data_name_10_string),
      &test_key_name_10,
      test_key_name_10_string,
      strlen(test_key_name_10_string),
      expected_rule_compilation_return_10,
      expected_match_10,
      &trust_schema_test_results[9]
    },
    {
      trust_schema_test_names,
      10,
      &test_rule_11,
      test_rule_11_data_pattern_string,
      strlen(test_rule_11_data_pattern_string),
      test_rule_11_key_pattern_string,
      strlen(test_rule_11_key_pattern_string),
      &test_data_name_11,
      test_data_name_11_string,
      strlen(test_data_name_11_string),
      &test_key_name_11,
      test_key_name_11_string,
      strlen(test_key_name_11_string),
      expected_rule_compilation_return_11,
      expected_match_11,
      &trust_schema_test_results[10]
    },
    {
      trust_schema_test_names,
      11,
      &test_rule_12,
      test_rule_12_data_pattern_string,
      strlen(test_rule_12_data_pattern_string),
      test_rule_12_key_pattern_string,
      strlen(test_rule_12_key_pattern_string),
      &test_data_name_12,
      test_data_name_12_string,
      strlen(test_data_name_12_string),
      &test_key_name_12,
      test_key_name_12_string,
      strlen(test_key_name_12_string),
      expected_rule_compilation_return_12,
      expected_match_12,
      &trust_schema_test_results[11]
    },

};

ndn_trust_schema_rule_t test_rule_1;
ndn_name_t test_data_name_1;
ndn_name_t test_key_name_1;

ndn_trust_schema_rule_t test_rule_2;
ndn_name_t test_data_name_2;
ndn_name_t test_key_name_2;

ndn_trust_schema_rule_t test_rule_3;
ndn_name_t test_data_name_3;
ndn_name_t test_key_name_3;

ndn_trust_schema_rule_t test_rule_4;
ndn_name_t test_data_name_4;
ndn_name_t test_key_name_4;

ndn_trust_schema_rule_t test_rule_5;
ndn_name_t test_data_name_5;
ndn_name_t test_key_name_5;

ndn_trust_schema_rule_t test_rule_6;
ndn_name_t test_data_name_6;
ndn_name_t test_key_name_6;

ndn_trust_schema_rule_t test_rule_7;
ndn_name_t test_data_name_7;
ndn_name_t test_key_name_7;

ndn_trust_schema_rule_t test_rule_8;
ndn_name_t test_data_name_8;
ndn_name_t test_key_name_8;

ndn_trust_schema_rule_t test_rule_9;
ndn_name_t test_data_name_9;
ndn_name_t test_key_name_9;

ndn_trust_schema_rule_t test_rule_10;
ndn_name_t test_data_name_10;
ndn_name_t test_key_name_10;

ndn_trust_schema_rule_t test_rule_11;
ndn_name_t test_data_name_11;
ndn_name_t test_key_name_11;

ndn_trust_schema_rule_t test_rule_12;
ndn_name_t test_data_name_12;
ndn_name_t test_key_name_12;
