
#include "ndn-trust-schema.h"

#include "../ndn-lite/ndn-error-code.h"

#include <stdio.h>

int
ndn_trust_schema_rule_from_string(ndn_trust_schema_rule_t* rule, const char* string, uint32_t size) {

  ndn_trust_schema_rule_component_t component;
  ndn_trust_schema_rule_component_from_string(&component, string, size);

}
