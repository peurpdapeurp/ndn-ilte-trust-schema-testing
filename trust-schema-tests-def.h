
/*
 * Copyright (C) 2019 Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef TRUST_SCHEMA_TESTS_DEF_H
#define TRUST_SCHEMA_TESTS_DEF_H

#include "trust-schema-tests.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "../ndn-lite/ndn-error-code.h"
#include "../ndn-lite/encode/name.h"
#include "ndn-trust-schema-rule.h"

#define TRUST_SCHEMA_NUM_TESTS 11

extern char *trust_schema_test_names[TRUST_SCHEMA_NUM_TESTS];

extern bool trust_schema_test_results[TRUST_SCHEMA_NUM_TESTS];

extern trust_schema_test_t trust_schema_tests[TRUST_SCHEMA_NUM_TESTS];

extern ndn_trust_schema_rule_t test_rule_1;
#define test_rule_1_data_pattern_string "<>*<apple>"
#define test_rule_1_key_pattern_string "<>*<apple>"
extern ndn_name_t test_data_name_1;
#define test_data_name_1_string "/test/apple"
extern ndn_name_t test_key_name_1;
#define test_key_name_1_string "/whatever/apple"
#define expected_rule_compilation_return_1 (NDN_SUCCESS)
#define expected_match_1 true

extern ndn_trust_schema_rule_t test_rule_2;
#define test_rule_2_data_pattern_string "<>*<apple>"
#define test_rule_2_key_pattern_string "<apple>"
extern ndn_name_t test_data_name_2;
#define test_data_name_2_string "/apple/appletest/not_apple"
extern ndn_name_t test_key_name_2;
#define test_key_name_2_string "/apple"
#define expected_rule_compilation_return_2 (NDN_SUCCESS)
#define expected_match_2 false

extern ndn_trust_schema_rule_t test_rule_3;
#define test_rule_3_data_pattern_string "<apple><>*"
#define test_rule_3_key_pattern_string "<apple><>*"
extern ndn_name_t test_data_name_3;
#define test_data_name_3_string "/apple/test/test/apple/test/banana"
extern ndn_name_t test_key_name_3;
#define test_key_name_3_string "/apple/banana/test/apple/apple"
#define expected_rule_compilation_return_3 (NDN_SUCCESS)
#define expected_match_3 true

extern ndn_trust_schema_rule_t test_rule_4;
#define test_rule_4_data_pattern_string "<apple><>*"
#define test_rule_4_key_pattern_string "<apple>"
extern ndn_name_t test_data_name_4;
#define test_data_name_4_string "/not_apple/test/test/apple/test/banana"
extern ndn_name_t test_key_name_4;
#define test_key_name_4_string "/apple"
#define expected_rule_compilation_return_4 (NDN_SUCCESS)
#define expected_match_4 false

extern ndn_trust_schema_rule_t test_rule_5;
#define test_rule_5_data_pattern_string "<>*<apple><>*"
#define test_rule_5_key_pattern_string "<>*<apple><>*"
extern ndn_name_t test_data_name_5;
#define test_data_name_5_string "/banana/banana/what/apple/haha/yes/there"
extern ndn_name_t test_key_name_5;
#define test_key_name_5_string "/beem/bom/bam/apple/beem/boom/bam/bop"
#define expected_rule_compilation_return_5 (NDN_SUCCESS)
#define expected_match_5 true

extern ndn_trust_schema_rule_t test_rule_6;
#define test_rule_6_data_pattern_string "<>*<apple><>*"
#define test_rule_6_key_pattern_string "<apple>"
extern ndn_name_t test_data_name_6;
#define test_data_name_6_string "/banana/banana/banana/banana/not_apple/banana"
extern ndn_name_t test_key_name_6;
#define test_key_name_6_string "/apple"
#define expected_rule_compilation_return_6 (NDN_SUCCESS)
#define expected_match_6 false

extern ndn_trust_schema_rule_t test_rule_7;
#define test_rule_7_data_pattern_string "<apple><banana>"
#define test_rule_7_key_pattern_string "<banana><apple><kiwi>"
extern ndn_name_t test_data_name_7;
#define test_data_name_7_string "/apple/banana"
extern ndn_name_t test_key_name_7;
#define test_key_name_7_string "/banana/apple/kiwi"
#define expected_rule_compilation_return_7 (NDN_SUCCESS)
#define expected_match_7 true

extern ndn_trust_schema_rule_t test_rule_8;
#define test_rule_8_data_pattern_string "<apple><banana>"
#define test_rule_8_key_pattern_string "<apple>"
extern ndn_name_t test_data_name_8;
#define test_data_name_8_string "/apple/banana/kiwi"
extern ndn_name_t test_key_name_8;
#define test_key_name_8_string "/apple"
#define expected_rule_compilation_return_8 (NDN_SUCCESS)
#define expected_match_8 false

extern ndn_trust_schema_rule_t test_rule_9;
#define test_rule_9_data_pattern_string "<>*"
#define test_rule_9_key_pattern_string "<>*"
extern ndn_name_t test_data_name_9;
#define test_data_name_9_string "/apple/banana/kiwi"
extern ndn_name_t test_key_name_9;
#define test_key_name_9_string "/anything/goes/whatever"
#define expected_rule_compilation_return_9 (NDN_SUCCESS)
#define expected_match_9 true

extern ndn_trust_schema_rule_t test_rule_10;
#define test_rule_10_data_pattern_string "[t.*t]"
#define test_rule_10_key_pattern_string "[^banana.*]"
extern ndn_name_t test_data_name_10;
#define test_data_name_10_string "/test"
extern ndn_name_t test_key_name_10;
#define test_key_name_10_string "/banana_nuggets"
#define expected_rule_compilation_return_10 (NDN_SUCCESS)
#define expected_match_10 true

extern ndn_trust_schema_rule_t test_rule_11;
#define test_rule_11_data_pattern_string "[^banana.*]"
#define test_rule_11_key_pattern_string "<apple>"
extern ndn_name_t test_data_name_11;
#define test_data_name_11_string "/apple_banana_nuggets"
extern ndn_name_t test_key_name_11;
#define test_key_name_11_string "/apple"
#define expected_rule_compilation_return_11 (NDN_SUCCESS)
#define expected_match_11 false

#endif // TRUST_SCHEMA_TESTS_DEF_H
