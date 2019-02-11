
#ifndef NDN_TRUST_SCHEMA_PATTERN_H
#define NDN_TRUST_SCHEMA_PATTERN_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "ndn-trust-schema-pattern-component.h"

#include "../ndn-lite/ndn-constants.h"
#include "../ndn-lite/ndn-error-code.h"

/**
 * The structure to represent the NDN Trust Schema pattern.
 * This structure is memory expensive so please be careful when using it.
 */
typedef struct ndn_trust_schema_pattern {
  /**
   * The array of schema components contained in this schema pattern (not including T and L)
   */
  ndn_trust_schema_pattern_component_t components[NDN_TRUST_SCHEMA_PATTERN_COMPONENTS_SIZE];
  /**
   * The number of schema components
   */
  uint32_t components_size;
} ndn_trust_schema_pattern_t;

/**
 * Appends a component to the end of a pattern. This function will do memory copy.
 * @param name. Output. The pattern to append to.
 * @param component. Input. The name component to append with.
 * @return 0 if there is no error.
 */
static inline int
ndn_trust_schema_pattern_append_component(ndn_trust_schema_pattern_t *pattern, const ndn_trust_schema_pattern_component_t* component)
{
  printf("In ndn_trust_schema_pattern_append_component, value of pattern->components_size + 1: %d\n", pattern->components_size + 1);
  
  if (pattern->components_size + 1 <= NDN_NAME_COMPONENTS_SIZE) {
    memcpy(pattern->components + pattern->components_size, component, sizeof(ndn_trust_schema_pattern_component_t));
    pattern->components_size++;

    printf("In ndn_trust_schema_pattern_append_component, increased components_size from %d to %d.\n", pattern->components_size - 1, pattern->components_size);
    
    return 0;
  }
  else
    return NDN_OVERSIZE;
}

/**
 * Init an NDN Trust Schema pattern from a string. This function will do memory copy and
 * only support regular string; not support URI currently.
 * @param pattern. Output. The NDN Trust Schema pattern to be inited.
 * @param string. Input. The string from which the NDN Trust Schema pattern is inited.
 * @param size. Input. Size of the input string.
 * @return 0 if there is no error.
 */
int
ndn_trust_schema_pattern_from_string(ndn_trust_schema_pattern_t* pattern, const char* string, uint32_t size);


#endif // NDN_TRUST_SCHEMA_PATTERN_H
