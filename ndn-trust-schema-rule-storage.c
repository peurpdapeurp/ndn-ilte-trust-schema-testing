
#include "ndn-trust-schema-rule-storage.h"

#include <stdio.h>

static ndn_rule_storage_t ndn_rule_storage;

// returns 0 if buffer contained only zeros
int _check_buffer_all_zeros(const char *buf, int buf_size) {
  int sum = 0;
  for (int i = 0; i < buf_size; i++) {
    sum |= buf[i];
  }
  return sum;
}

ndn_rule_storage_t*
get_ndn_rule_storage_instance() {
  return &ndn_rule_storage;
}

void
ndn_rule_storage_init() {
  for (int i = 0; i < NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES; i++) {
    memset(&ndn_rule_storage.rule_objects[i], 0, sizeof(ndn_trust_schema_rule_t));
    ndn_rule_storage.rule_names[i].name[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_BUFFER_SIZE-1] = '\0';
  }
}

int
ndn_rule_storage_get_rule(const char *rule_name, ndn_trust_schema_rule_t *rule) {
  int ret_val = -1;
  for (int i = 0; i < NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES; i++) {
    if (strcmp((const char *)&ndn_rule_storage.rule_names[i].name, rule_name) == 0 &&
	strlen((const char *)&ndn_rule_storage.rule_names[i].name) == strlen(rule_name)) {
      printf("Found a matching rule in the rule_names array at position %d\n", i);
      rule = &ndn_rule_storage.rule_objects[i];
      return NDN_SUCCESS;
    }
  }
  return NDN_TRUST_SCHEMA_RULE_NOT_FOUND;  
}

int
ndn_rule_storage_add_rule(const char* rule_name, const ndn_trust_schema_rule_t *rule) {
  int ret_val = -1;
  for (int i = 0; i < NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES; i++) {
    if (_check_buffer_all_zeros((uint8_t *) &ndn_rule_storage.rule_objects[i], sizeof(ndn_trust_schema_rule_t)) == 0) {
      printf("Found an empty slot in the rule_objects array at position %d\n", i);
      ret_val = ndn_trust_schema_rule_copy(rule, &ndn_rule_storage.rule_objects[i]);
      if (ret_val != 0) return ret_val;
      if (strlen(rule_name) > NDN_TRUST_SCHEMA_RULE_NAME_MAX_LENGTH)
	return NDN_TRUST_SCHEMA_RULE_NAME_TOO_LONG;
      memcpy(&ndn_rule_storage.rule_names[i].name, rule_name, strlen(rule_name));
      ndn_rule_storage.rule_names[i].name[strlen(rule_name)] = '\0';
      return NDN_SUCCESS;
    }
  }
  return NDN_TRUST_SCHEMA_RULE_STORAGE_FULL;
}

int
ndn_rule_storage_remove_rule(const char* rule_name) {
  
}

