
#ifndef NDN_TRUST_SCHEMA_RULE_STORAGE_H
#define NDN_TRUST_SCHEMA_RULE_STORAGE_H

#include "ndn-trust-schema-rule.h"
#include "../ndn-lite/ndn-constants.h"

typedef struct {
  char name[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_BUFFER_SIZE];
} ndn_rule_name_t;

typedef struct {
  ndn_trust_schema_rule_t rule_objects[NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES];
  ndn_rule_name_t rule_names[NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES];
} ndn_rule_storage_t;

/**@brief There should be only one ndn_rule_storage_t. Use this function
 *          to get the singleton instance. If the instance has not been initialized,
 *          call ndn_rule_storage_init first.
 */
ndn_rule_storage_t*
get_ndn_rule_storage_instance();

void
ndn_rule_storage_init();

int
ndn_rule_storage_get_rule(const char *rule_name, ndn_trust_schema_rule_t *rule);

int
ndn_rule_storage_add_rule(const char* rule_name, const ndn_trust_schema_rule_t *rule);

int
ndn_rule_storage_remove_rule(const char* rule_name);
			  
#endif // NDN_TRUST_SCHEMA_RULE_STORAGE_H
