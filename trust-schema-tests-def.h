
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

#include "../ndn-lite/encode/name.h"
#include "ndn-trust-schema-rule.h"

#define TRUST_SCHEMA_NUM_TESTS 1

extern char *trust_schema_test_names[TRUST_SCHEMA_NUM_TESTS];

extern bool trust_schema_test_results[TRUST_SCHEMA_NUM_TESTS];

extern trust_schema_test_t trust_schema_tests[TRUST_SCHEMA_NUM_TESTS];

extern ndn_trust_schema_rule_t test_rule_1;
#define test_rule_1_data_pattern_string "<test><test><test>"
#define test_rule_1_key_pattern_string "<test><test><test>"

extern ndn_name_t test_data_name_1;
#define test_data_name_1_string "/test/test/test"

extern ndn_name_t test_key_name_1;
#define test_key_name_1_string "/test/test/test"


#endif // TRUST_SCHEMA_TESTS_DEF_H
