
#include <stdio.h>

#include "../ndn-lite/encode/name.h"
#include "../ndn-lite/ndn-error-code.h"
#include "ndn-trust-schema.h"

#include "tiny-regex-c/re.h"

static const char result_success[] = "SUCCESS";
static const char result_failure[] = "FAILURE";

static ndn_trust_schema_rule_t test_rule_1;
static char test_rule_data_pattern_string_1[] = "<test><test><test>";
static char test_rule_key_pattern_string_1[] = "<test><test><test>";

/* static ndn_trust_schema_rule_t test_rule_2; */
/* static char test_rule_data_pattern_string_2[] = "<test><test>[t.*t]"; */
/* static char test_rule_key_pattern_string_2[] = "<test><test>[.es.]"; */

/* static ndn_trust_schema_rule_t test_rule_3; */
/* static char test_rule_data_pattern_string_3[] = "(<test>)<test>(<>)"; */
/* static char test_rule_key_pattern_string_3[] = "(<test>)(<test>)(<>)"; */

/* static ndn_trust_schema_rule_t test_rule_4; */
/* static char test_rule_data_pattern_string_4[] = "(<>*)<test>"; */
/* static char test_rule_key_pattern_string_4[] = "<test>(<>*)<test>"; */

/* static ndn_trust_schema_rule_t test_rule_5; */
/* static char test_rule_data_pattern_string_5[] = "(<>*)<test>"; */
/* static char test_rule_key_pattern_string_5[] = "\\0<test>"; */


static ndn_name_t test_data_name_1;
static char test_data_name_string_1[] = "/test/test/test";

/* static ndn_name_t test_data_name_2; */
/* static char test_data_name_string_2[] = "/test/test/fail"; */

/* static ndn_name_t test_data_name_3; */
/* static char test_data_name_string_3[] = "/whatever/i/dont/know/test"; */

/* static ndn_name_t test_data_name_4; */
/* static char test_data_name_string_4[] = "/test/whatever/i/dont/know"; */

static ndn_name_t test_key_name_1;
static char test_key_name_string_1[] = "/test/test/test";

/* static ndn_name_t test_key_name_2; */
/* static char test_key_name_string_2[] = "/test/test/fail"; */

/* static ndn_name_t test_key_name_3; */
/* static char test_key_name_string_3[] = "/test/whatever/i/dont/know/test"; */

int _initialize_test_objects() {

  int ret_val = -1;
  
  printf("\nThis is a test of a potential schematized trust implementation.\n");
  printf("----------------------------------------------------------------\n\n");  

  ret_val = ndn_name_from_string(&test_data_name_1, test_data_name_string_1, sizeof(test_data_name_string_1));
  if (ret_val != NDN_SUCCESS) {
    printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val);
    return ret_val;
  }
  /* ret_val = ndn_name_from_string(&test_data_name_2, test_data_name_string_2, sizeof(test_data_name_string_2)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val); */
  /*   return ret_val; */
  /* } */
  /* ret_val = ndn_name_from_string(&test_data_name_3, test_data_name_string_3, sizeof(test_data_name_string_3)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val); */
  /*   return ret_val; */
  /* } */
  /* ret_val = ndn_name_from_string(&test_data_name_4, test_data_name_string_4, sizeof(test_data_name_string_4)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val); */
  /*   return ret_val; */
  /* } */
  
  ret_val = ndn_name_from_string(&test_key_name_1, test_key_name_string_1, sizeof(test_key_name_string_1));
  if (ret_val != NDN_SUCCESS) {
    printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val);
    return ret_val;
  }
  /* ret_val = ndn_name_from_string(&test_key_name_2, test_key_name_string_2, sizeof(test_key_name_string_2)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val); */
  /*   return ret_val; */
  /* } */
  /* ret_val = ndn_name_from_string(&test_key_name_3, test_key_name_string_3, sizeof(test_key_name_string_3)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_name_from_string failed, error code: %d\n", ret_val); */
  /*   return ret_val; */
  /* } */
  
  ret_val = ndn_trust_schema_rule_from_strings(&test_rule_1,
  					       test_rule_data_pattern_string_1, sizeof(test_rule_data_pattern_string_1),
  					       test_rule_key_pattern_string_1, sizeof(test_rule_key_pattern_string_1));
  if (ret_val != NDN_SUCCESS) {
    printf("Call to ndn_trust_schema_rule_from_strings failed, error code: %d\n", ret_val);
    return ret_val;
  }
  printf("\n");
  /* ret_val = ndn_trust_schema_rule_from_strings(&test_rule_2, */
  /* 					       test_rule_data_pattern_string_2, sizeof(test_rule_data_pattern_string_2), */
  /* 					       test_rule_key_pattern_string_2, sizeof(test_rule_key_pattern_string_2)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_trust_schema_rule_from_strings failed, error code: %d\n", ret_val); */
  /*   return ret_val; */
  /* } */
  /* printf("\n"); */
  /* ret_val = ndn_trust_schema_rule_from_strings(&test_rule_3, */
  /* 					       test_rule_data_pattern_string_3, sizeof(test_rule_data_pattern_string_3), */
  /* 					       test_rule_key_pattern_string_3, sizeof(test_rule_key_pattern_string_3)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_trust_schema_rule_from_strings failed, error code: %d\n", ret_val); */
  /*   return ret_val; */
  /* } */
  /* printf("\n"); */
  /* ret_val = ndn_trust_schema_rule_from_strings(&test_rule_4, */
  /* 					       test_rule_data_pattern_string_4, sizeof(test_rule_data_pattern_string_4), */
  /* 					       test_rule_key_pattern_string_4, sizeof(test_rule_key_pattern_string_4)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_trust_schema_rule_from_strings failed, error code: %d\n", ret_val); */
  /*   return ret_val; */
  /* } */
  /* printf("\n"); */
  /* ret_val = ndn_trust_schema_rule_from_strings(&test_rule_5, */
  /* 					       test_rule_data_pattern_string_5, sizeof(test_rule_data_pattern_string_5), */
  /* 					       test_rule_key_pattern_string_5, sizeof(test_rule_key_pattern_string_5)); */
  /* if (ret_val != NDN_SUCCESS) { */
  /*   printf("Call to ndn_trust_schema_rule_from_strings failed, error code: %d\n", ret_val); */
  /*   return ret_val; */
  /* } */
  /* printf("\n"); */

  
  printf("Finished initializing test objects.\n");
  printf("\n------------------------------------------------------------------------------------------\n\n");
  
  return 0;
}

void run_test(ndn_trust_schema_rule_t *test_rule,
	        const char *test_rule_data_pattern_string, const char*test_rule_key_pattern_string,
	      ndn_name_t *test_data_name, const char *test_data_name_string,
	      ndn_name_t *test_key_name, const char *test_key_name_string) {
  int ret_val = -1;
  ret_val = ndn_trust_schema_verify_data_name_key_name_pair(test_rule, test_data_name, test_key_name);
  const char *result;
  if (ret_val != 0)
    result = result_failure;
  else
    result = result_success;

  printf("Result of call to ndn_trust_schema_verify_key_name for following parameters:\n"
	 "Rule data pattern: %s\n"
	 "Rule key pattern: %s\n"
	 "Data name: %s\n"
	 "Key name: %s\n"
	 "Result: %s\n",
	 test_rule_data_pattern_string, test_rule_key_pattern_string, test_data_name_string, test_key_name_string, result);
  if (ret_val != 0)
    printf("Error code: %d\n", ret_val);
  
  printf("\n------------------------------------------------------------------------------------------\n\n");
}

int main() {

  int ret_val = -1;

  ret_val = _initialize_test_objects();
  if (ret_val != 0) {
    printf("Initialization of test objects failed.\n");
    
    const char pattern[] = "^\\\\[0-9]";
    const char string[] = "\\0";
    printf("Result of trying to match %s with %s: %d\n", pattern, string, re_match(pattern, string));
    
    return -1;
  }
  
  run_test(&test_rule_1,
  	   test_rule_data_pattern_string_1, test_rule_key_pattern_string_1,
  	   &test_data_name_1, test_data_name_string_1,
  	   &test_key_name_1, test_key_name_string_1);

  /* run_test(&test_rule_1, */
  /* 	   test_rule_data_pattern_string_1, test_rule_key_pattern_string_1, */
  /* 	   &test_data_name_1, test_data_name_string_1, */
  /* 	   &test_key_name_2, test_key_name_string_2); */

  /* run_test(&test_rule_2, */
  /* 	   test_rule_data_pattern_string_2, test_rule_key_pattern_string_2, */
  /* 	   &test_data_name_1, test_data_name_string_1, */
  /* 	   &test_key_name_1, test_key_name_string_1); */

  /* run_test(&test_rule_2, */
  /* 	   test_rule_data_pattern_string_2, test_rule_key_pattern_string_2, */
  /* 	   &test_data_name_1, test_data_name_string_1, */
  /* 	   &test_key_name_2, test_key_name_string_2); */
  
  /* run_test(&test_rule_3, */
  /* 	   test_rule_data_pattern_string_3, test_rule_key_pattern_string_3, */
  /* 	   &test_data_name_1, test_data_name_string_1, */
  /* 	   &test_key_name_1, test_key_name_string_1); */
  
  /* run_test(&test_rule_4, */
  /* 	   test_rule_data_pattern_string_4, test_rule_key_pattern_string_4, */
  /* 	   &test_data_name_3, test_data_name_string_3, */
  /* 	   &test_key_name_3, test_key_name_string_3); */

  /* run_test(&test_rule_5, */
  /* 	   test_rule_data_pattern_string_5, test_rule_key_pattern_string_5, */
  /* 	   &test_data_name_4, test_data_name_string_4, */
  /* 	   &test_key_name_3, test_key_name_string_3); */

  /* run_test(&test_rule_5, */
  /* 	   test_rule_data_pattern_string_5, test_rule_key_pattern_string_5, */
  /* 	   &test_data_name_1, test_data_name_string_1, */
  /* 	   &test_key_name_1, test_key_name_string_1); */


  return 0;
}
