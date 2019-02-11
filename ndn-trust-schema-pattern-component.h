
#ifndef NDN_TRUST_SCHEMA_PATTERN_COMPONENT_H
#define NDN_TRUST_SCHEMA_PATTERN_COMPONENT_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tiny-regex-c/re.h"

#include "../ndn-lite/ndn-constants.h"
#include "../ndn-lite/ndn-error-code.h"

#include "ndn-trust-schema-common.h"

/**
 * The structure to represent an NDN Trust Schema Pattern Component.
 */
typedef struct ndn_trust_schema_pattern_component {
  /**
   * The component type.
   */
  uint32_t type;
  /**
   * The value which the trust schema pattern component holds. Format of the buffer
   * depends on the trust schema pattern component type.
   */
  uint8_t value[NDN_TRUST_SCHEMA_PATTERN_COMPONENT_BUFFER_SIZE];
  /**
   * The size of component value buffer.
   */
  uint32_t size;
} ndn_trust_schema_pattern_component_t;

/**
 * Init an NDN Trust Schema pattern Component structure from caller supplied memory block.
 * The function will do memory copy
 * @param component. Output. The NDN Trust Schema pattern Component structure to be inited.
 * @param type. Input. NDN Trust Schema pattern Component Type to be set with.
 * @param value. Input. Memory block which holds the NDN Trust Schema Pattern Component Value.
 * @param size. Input. Size of input block.
 * @return 0 if there is no error.
 */
static inline int
ndn_trust_schema_pattern_component_from_buffer(ndn_trust_schema_pattern_component_t* component, uint32_t type,
					    const uint8_t* value, uint32_t size)
{
  if (size > NDN_NAME_COMPONENT_BUFFER_SIZE)
    return NDN_OVERSIZE;
  component->type = type;
  memcpy(component->value, value, size);
  component->size = size;
  return 0;
}

/**
 * Probes a string to get its trust schema pattern component type.
 * @param string. Input. String variable which will be probed for trust schema pattern component type.
 * @param size. Input. Size of input string.
 * @return Returns the trust schema pattern component type if there is no error and 
 *         the probing found a valid NDN trust schema pattern component type.
 */
static inline uint32_t
_probe_trust_schema_pattern_component_type(const char* string, uint32_t size)
{  
  printf("In _probe_trust_schema_pattern_component_type, string passed in: %s\n", string);

  int ret_val = -1;

  if (re_match(_multiple_wildcard_rgxp, string) != TINY_REGEX_C_FAIL) {
    printf("In _probe_trust_schema_pattern_component_type, found a match for %s.\n", _multiple_wildcard_rgxp);
    return NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE;
  }
  else if (re_match(_single_wildcard_rgxp, string) != TINY_REGEX_C_FAIL) {
    printf("In _probe_trust_schema_pattern_component_type, found a match for %s.\n", _single_wildcard_rgxp);
    return NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT;
  }
  else if (re_match(_single_name_rgxp, string) != TINY_REGEX_C_FAIL) {
    printf("In _probe_trust_schema_pattern_component_type, found a match for %s.\n", _single_name_rgxp);
    return NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT;
  }
  else if (re_match(_subpattern_match_rgxp, string) != TINY_REGEX_C_FAIL) {
    printf("In _probe_trust_schema_pattern_component_type, found a match for %s.\n", _subpattern_match_rgxp);
    return NDN_TRUST_SCHEMA_SUBPATTERN_MATCH;
  }
  else if (re_match(_function_ref_rgxp, string) != TINY_REGEX_C_FAIL) {
    printf("In _probe_trust_schema_pattern_component_type, found a match for %s.\n", _function_ref_rgxp);
    return NDN_TRUST_SCHEMA_WILDCARD_SPECIALIZER;
  }
  else if (re_match(_rule_ref_rgxp, string) != TINY_REGEX_C_FAIL) {
    printf("In _probe_trust_schema_pattern_component_type, found a match for %s.\n", _rule_ref_rgxp);
    return NDN_TRUST_SCHEMA_RULE_REF;
  }
  else {
    printf("In _probe_trust_schema_pattern_component_type, found an unrecognizable pattern component.\n");
    return NDN_TRUST_SCHEMA_PATTERN_COMPONENT_UNRECOGNIZED_TYPE;
  }
}

/**
 * Init an NDN Trust Schema Pattern Component structure from string. The size should not include the terminating '\0'
 * character. The function will do memory copy.
 * @param component. Output. The NDN Trust Schema Pattern Component structure to be inited.
 * @param string. Input. String variable which NDN Trust Schema pattern component initing from.
 * @param size. Input. Size of input string.
 * @return 0 if there is no error.
 */
int
ndn_trust_schema_pattern_component_from_string(ndn_trust_schema_pattern_component_t* component, const char* string, uint32_t size);

#endif // NDN_TRUST_SCHEMA_PATTERN_COMPONENT_H
