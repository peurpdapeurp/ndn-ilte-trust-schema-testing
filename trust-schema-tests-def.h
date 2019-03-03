
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

#define TRUST_SCHEMA_NUM_TESTS 21

extern char *trust_schema_test_names[TRUST_SCHEMA_NUM_TESTS];

extern bool trust_schema_test_results[TRUST_SCHEMA_NUM_TESTS];

extern trust_schema_test_t trust_schema_tests[TRUST_SCHEMA_NUM_TESTS];

static ndn_trust_schema_rule_t test_rule_0;
#define test_rule_0_data_pattern_string "<>*<apple>"
#define test_rule_0_key_pattern_string "<>*<apple>"
static ndn_name_t test_data_name_0;
#define test_data_name_0_string "/test/apple"
static ndn_name_t test_key_name_0;
#define test_key_name_0_string "/whatever/apple"
#define expected_rule_compilation_return_0 (NDN_SUCCESS)
#define expected_match_0 (NDN_SUCCESS)

static ndn_trust_schema_rule_t test_rule_1;
#define test_rule_1_data_pattern_string "<>*<apple>"
#define test_rule_1_key_pattern_string "<apple>"
static ndn_name_t test_data_name_1;
#define test_data_name_1_string "/apple/appletest/not_apple"
static ndn_name_t test_key_name_1;
#define test_key_name_1_string "/apple"
#define expected_rule_compilation_return_1 (NDN_SUCCESS)
#define expected_match_1 (NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH)

static ndn_trust_schema_rule_t test_rule_2;
#define test_rule_2_data_pattern_string "<apple><>*"
#define test_rule_2_key_pattern_string "<apple><>*"
static ndn_name_t test_data_name_2;
#define test_data_name_2_string "/apple/test/test/apple/test/banana"
static ndn_name_t test_key_name_2;
#define test_key_name_2_string "/apple/banana/test/apple/apple"
#define expected_rule_compilation_return_2 (NDN_SUCCESS)
#define expected_match_2 (NDN_SUCCESS)

static ndn_trust_schema_rule_t test_rule_3;
#define test_rule_3_data_pattern_string "<apple><>*"
#define test_rule_3_key_pattern_string "<apple>"
static ndn_name_t test_data_name_3;
#define test_data_name_3_string "/not_apple/test/test/apple/test/banana"
static ndn_name_t test_key_name_3;
#define test_key_name_3_string "/apple"
#define expected_rule_compilation_return_3 (NDN_SUCCESS)
#define expected_match_3 (NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH)

static ndn_trust_schema_rule_t test_rule_4;
#define test_rule_4_data_pattern_string "<>*<apple><>*"
#define test_rule_4_key_pattern_string "<>*<apple><>*"
static ndn_name_t test_data_name_4;
#define test_data_name_4_string "/banana/banana/what/apple/haha/yes/there"
static ndn_name_t test_key_name_4;
#define test_key_name_4_string "/beem/bom/bam/apple/beem/boom/bam/bop"
#define expected_rule_compilation_return_4 (NDN_SUCCESS)
#define expected_match_4 (NDN_SUCCESS)

static ndn_trust_schema_rule_t test_rule_5;
#define test_rule_5_data_pattern_string "<>*<apple><>*"
#define test_rule_5_key_pattern_string "<apple>"
static ndn_name_t test_data_name_5;
#define test_data_name_5_string "/banana/banana/banana/banana/not_apple/banana"
static ndn_name_t test_key_name_5;
#define test_key_name_5_string "/apple"
#define expected_rule_compilation_return_5 (NDN_SUCCESS)
#define expected_match_5 (NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH)

static ndn_trust_schema_rule_t test_rule_6;
#define test_rule_6_data_pattern_string "<apple><banana>"
#define test_rule_6_key_pattern_string "<banana><apple><kiwi>"
static ndn_name_t test_data_name_6;
#define test_data_name_6_string "/apple/banana"
static ndn_name_t test_key_name_6;
#define test_key_name_6_string "/banana/apple/kiwi"
#define expected_rule_compilation_return_6 (NDN_SUCCESS)
#define expected_match_6 (NDN_SUCCESS)

static ndn_trust_schema_rule_t test_rule_7;
#define test_rule_7_data_pattern_string "<apple><banana>"
#define test_rule_7_key_pattern_string "<apple>"
static ndn_name_t test_data_name_7;
#define test_data_name_7_string "/apple/banana/kiwi"
static ndn_name_t test_key_name_7;
#define test_key_name_7_string "/apple"
#define expected_rule_compilation_return_7 (NDN_SUCCESS)
#define expected_match_7 (NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH)

static ndn_trust_schema_rule_t test_rule_8;
#define test_rule_8_data_pattern_string "<>*"
#define test_rule_8_key_pattern_string "<>*"
static ndn_name_t test_data_name_8;
#define test_data_name_8_string "/apple/banana/kiwi"
static ndn_name_t test_key_name_8;
#define test_key_name_8_string "/anything/goes/whatever"
#define expected_rule_compilation_return_8 (NDN_SUCCESS)
#define expected_match_8 (NDN_SUCCESS)

static ndn_trust_schema_rule_t test_rule_9;
#define test_rule_9_data_pattern_string "[t.*t]"
#define test_rule_9_key_pattern_string "[^banana.*]"
static ndn_name_t test_data_name_9;
#define test_data_name_9_string "/test"
static ndn_name_t test_key_name_9;
#define test_key_name_9_string "/banana_nuggets"
#define expected_rule_compilation_return_9 (NDN_SUCCESS)
#define expected_match_9 (NDN_SUCCESS)

static ndn_trust_schema_rule_t test_rule_10;
#define test_rule_10_data_pattern_string "[^banana.*]"
#define test_rule_10_key_pattern_string "<apple>"
static ndn_name_t test_data_name_10;
#define test_data_name_10_string "/apple_banana_nuggets"
static ndn_name_t test_key_name_10;
#define test_key_name_10_string "/apple"
#define expected_rule_compilation_return_10 (NDN_SUCCESS)
#define expected_match_10 (NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH)

static ndn_trust_schema_rule_t test_rule_11;
#define test_rule_11_data_pattern_string "<>*<>*<>*"
#define test_rule_11_key_pattern_string "<apple>"
static ndn_name_t test_data_name_11;
#define test_data_name_11_string "/apple"
static ndn_name_t test_key_name_11;
#define test_key_name_11_string "/apple"
#define expected_rule_compilation_return_11 (NDN_TRUST_SCHEMA_PATTERN_INVALID_FORMAT)
#define expected_match_11 (NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH)

static ndn_trust_schema_rule_t test_rule_12;
#define test_rule_12_data_pattern_string "(<>)"
#define test_rule_12_key_pattern_string "\\0"
static ndn_name_t test_data_name_12;
#define test_data_name_12_string "/apple"
static ndn_name_t test_key_name_12;
#define test_key_name_12_string "/apple"
#define expected_rule_compilation_return_12 (NDN_SUCCESS)
#define expected_match_12 (NDN_SUCCESS)

static ndn_trust_schema_rule_t test_rule_13;
#define test_rule_13_data_pattern_string "(<>)"
#define test_rule_13_key_pattern_string "\\0"
static ndn_name_t test_data_name_13;
#define test_data_name_13_string "/apple"
static ndn_name_t test_key_name_13;
#define test_key_name_13_string "/banana"
#define expected_rule_compilation_return_13 (NDN_SUCCESS)
#define expected_match_13 (NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH)

static ndn_trust_schema_rule_t test_rule_14;
#define test_rule_14_data_pattern_string "(<>)(<>*)"
#define test_rule_14_key_pattern_string "\\1<test>\\0"
static ndn_name_t test_data_name_14;
#define test_data_name_14_string "/apple/banana/kiwi"
static ndn_name_t test_key_name_14;
#define test_key_name_14_string "/banana/kiwi/test/apple"
#define expected_rule_compilation_return_14 (NDN_SUCCESS)
#define expected_match_14 (NDN_SUCCESS)

static ndn_trust_schema_rule_t test_rule_15;
#define test_rule_15_data_pattern_string "(<>)(<>*)"
#define test_rule_15_key_pattern_string "\\1<test>\\0"
static ndn_name_t test_data_name_15;
#define test_data_name_15_string "/apple/banana/kiwi"
static ndn_name_t test_key_name_15;
#define test_key_name_15_string "/banana/kiwi/apple"
#define expected_rule_compilation_return_15 (NDN_SUCCESS)
#define expected_match_15 (NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH)

static ndn_trust_schema_rule_t test_rule_16;
#define test_rule_16_data_pattern_string "(<>*)<kiwi>"
#define test_rule_16_key_pattern_string "\\0<test>"
static ndn_name_t test_data_name_16;
#define test_data_name_16_string "/kiwi"
static ndn_name_t test_key_name_16;
#define test_key_name_16_string "/test"
#define expected_rule_compilation_return_16 (NDN_SUCCESS)
#define expected_match_16 (NDN_SUCCESS)

static ndn_trust_schema_rule_t test_rule_17;
#define test_rule_17_data_pattern_string "(<>*)<kiwi>"
#define test_rule_17_key_pattern_string "\\0<test>"
static ndn_name_t test_data_name_17;
#define test_data_name_17_string "/kiwi"
static ndn_name_t test_key_name_17;
#define test_key_name_17_string "/kiwi"
#define expected_rule_compilation_return_17 (NDN_SUCCESS)
#define expected_match_17 (NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH)

static ndn_trust_schema_rule_t test_rule_18;
#define test_rule_18_data_pattern_string "(<>*)<test>"
#define test_rule_18_key_pattern_string "\\0<test>"
static ndn_name_t test_data_name_18;
#define test_data_name_18_string "/apple/banana/test"
static ndn_name_t test_key_name_18;
#define test_key_name_18_string "/apple/banana"
#define expected_rule_compilation_return_18 (NDN_SUCCESS)
#define expected_match_18 (NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH)

static ndn_trust_schema_rule_t test_rule_19;
#define test_rule_19_data_pattern_string "(<>*)<test><test>"
#define test_rule_19_key_pattern_string "\\0<test><test>"
static ndn_name_t test_data_name_19;
#define test_data_name_19_string "/test/test"
static ndn_name_t test_key_name_19;
#define test_key_name_19_string "/test/test/test"
#define expected_rule_compilation_return_19 (NDN_SUCCESS)
#define expected_match_19 (NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH)

static ndn_trust_schema_rule_t test_rule_20;
#define test_rule_20_data_pattern_string "(<>*)"
#define test_rule_20_key_pattern_string "rule_ref(\\0)"
static ndn_name_t test_data_name_20;
#define test_data_name_20_string "/test"
static ndn_name_t test_key_name_20;
#define test_key_name_20_string "/apple/banana/test"
#define expected_rule_compilation_return_20 (NDN_SUCCESS)
#define expected_match_20 (NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH)

#endif // TRUST_SCHEMA_TESTS_DEF_H
