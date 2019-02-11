
#include "ndn-trust-schema.h"

#include "../ndn-lite/ndn-error-code.h"
#include "../ndn-lite/ndn-constants.h"

#include <stdio.h>
#include <stdbool.h>

int
ndn_trust_schema_verify_data_name_key_name_pair(const ndn_trust_schema_rule_t* rule, const ndn_name_t* data_name, const ndn_name_t* key_name) {

  const char[] function_msg_prefix = "In ndn_trust_schema_verify_key_name, ";
  
  printf("%sprinting the types of pattern components in the rule's data name pattern:\n", function_msg_prefix);
  for (int i = 0; i < rule->data_pattern.components_size; i++) {
    switch (rule->data_pattern.components[i].type) {
      printf("Rule component i was a");
    case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT:
      printf(" single name component, with value: %.*s\n", rule->data_pattern.components[i].size, rule->data_pattern.components[i].value);
      break;
    default:
      printf(" rule component other than a single name component.\n");
    }
  }
  printf("\n");

  printf("%sprinting the types of pattern components in the rule's key name pattern:\n", function_msg_prefix);
  for (int i = 0; i < rule->key_pattern.components_size; i++) {
    switch (rule->key_pattern.components[i].type) {
      printf("Rule component i was a");
    case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT:
      printf(" single name component, with value: %.*s\n", rule->key_pattern.components[i].size, rule->key_pattern.components[i].value);
      break;
    default:
      printf(" rule component other than a single name component.\n");
    }
  }
  printf("\n");
  
  printf("%sprinting the data name:\n", function_msg_prefix);
  for (int i = 0; i < data_name->components_size; i++) {
    printf("/%.*s", data_name->components[i].size, data_name->components[i].value);
  }
  printf("\n\n");

  printf("%sprinting the key name:\n", function_msg_prefix);
  for (int i = 0; i < key_name->components_size; i++) {
    printf("/%.*s", key_name->components[i].size, key_name->components[i].value);
  }
  printf("\n\n");

  bool data_name_valid = true;
  bool key_name_valid = true;
  int rdpi = 0;
  int kni = 0;
  int dni = 0;

  // checking to see if the data's name matches the data pattern of the rule
  
  printf("Rule's data pattern components size: %d\n", rule->data_pattern.components_size);
  printf("data_name components size: %d\n", data_name->components_size);
  
  while (rdpi < rule->data_pattern.components_size && dni < data_name->components_size) {

    printf("Value of rdpi and dni: %d, %d\n", rdpi, dni);
    
    switch (rule->data_pattern.components[rdpi].type) {
    case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT:
      printf("%sfound single name component.\n", function_msg_prefix);
      if (memcmp(rule->data_pattern.components[rdpi].value, data_name->components[dni].value, rule->data_pattern.components[ri].size) != 0 ||
  	  rule->components[rdpi].size != data_name->components[kni].size) {
	printf("Found that data name was invalid.\n");
	printf("Value of rule->data_pattern.components[rdpi].value (size: %d):\n", rule->data_pattern.components[rdpi].size);
	for (int i = 0; i < rule->data_pattern.components[rdpi].size; i++) {
	  if (i > 0) printf(":");
	  printf("%02X", rule->data_pattern.components[rdpi].value[i]);
	}
	printf("\n");
	printf("Value of data_name->components[dni].value (size: %d):\n", data_name->components[dni].size);
	for (int i = 0; i < data_name->components[dni].size; i++) {
	  if (i > 0) printf(":");
	  printf("%02X", data_name->components[dni].value[i]);
	}
	printf("\n");
  	data_name_valid = false;
      }
      rdpi++;
      dni++;
      break;
    case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT:
      printf("In ndn_trust_Schema_verify_key_name, found wildcard name component.\n");
      ri++;
      kni++;
      dni++;
      break;
    case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE:
      printf("In ndn_trust_Schema_verify_key_name, found wildcard name component sequence.\n");
      break;
    }

    if (!data_name_valid)
      break;
  }

  /* // checking to see if key's name matches key pattern of the rule */

  /* printf("Rule's data pattern components size: %d\n", rule->data_pattern.components_size); */
  /* printf("key_name components size: %d\n", key_name->components_size); */
  /* printf("data_name components size: %d\n", data_name->components_size); */
  
  /* while (ri < rule->components_size && kni < key_name->components_size && dni < data_name->components_size) { */

  /*   printf("Value of ri, kni, dni: %d, %d, %d\n", ri, kni, dni); */
    
  /*   switch (rule->components[ri].type) { */
  /*   case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT: */
  /*     printf("%sfound single name component.\n", function_msg_prefix); */
  /*     if (memcmp(rule->components[ri].value, key_name->components[kni].value, rule->components[ri].size) != 0 || */
  /* 	  rule->components[ri].size != key_name->components[kni].size) { */
  /* 	printf("Found that key name was invalid.\n"); */
  /* 	printf("Value of rule->components[ri].value (size: %d):\n", rule->components[ri].size); */
  /* 	for (int i = 0; i < rule->components[ri].size; i++) { */
  /* 	  if (i > 0) printf(":"); */
  /* 	  printf("%02X", rule->components[ri].value[i]); */
  /* 	} */
  /* 	printf("\n"); */
  /* 	printf("Value of key_name->components[kni].value (size: %d):\n", key_name->components[kni].size); */
  /* 	for (int i = 0; i < key_name->components[kni].size; i++) { */
  /* 	  if (i > 0) printf(":"); */
  /* 	  printf("%02X", key_name->components[kni].value[i]); */
  /* 	} */
  /* 	printf("\n"); */
  /* 	key_name_valid = false; */
  /*     } */
  /*     ri++; */
  /*     kni++; */
  /*     dni++; */
  /*     break; */
  /*   case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT: */
  /*     printf("In ndn_trust_Schema_verify_key_name, found wildcard name component.\n"); */
  /*     ri++; */
  /*     kni++; */
  /*     dni++; */
  /*     break; */
  /*   case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE: */
  /*     printf("In ndn_trust_Schema_verify_key_name, found wildcard name component sequence.\n"); */
  /*     break; */
  /*   } */

  /*   if (!key_name_valid) */
  /*     break; */
  /* } */
  
  return (data_name_valid && key_name_valid) ? 0 : -1;
  
}
