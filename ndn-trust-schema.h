
#ifndef NDN_TRUST_SCHEMA_H
#define NDN_TRUST_SCHEMA_H

#include "../ndn-lite/ndn-constants.h"
#include "../ndn-lite/ndn-error-code.h"

#include "tiny-regex-c/re.h"

#include <string.h>
#include <stdio.h>

static char _single_name_rgxp[] = "^/<.+>$";
static char _single_wildcard_rgxp[] = "^/<>$";
static char _multiple_wildcard_rgxp[] = "^/<>\\*$";
static char _subpattern_match_rgxp[] = "^/(.+)$";
static char _function_ref_rgxp[] = "^/\\[.+\\]$";
static char _rule_ref_rgxp[] = "^.+(.+)$";
static char _rule_ref_args_rgxp[] = "(\\\\d*,?.*)$";
static int  TINY_REGEX_C_FAIL = -1;

/**
 * The structure to represent an NDN Trust Schema Pattern Component.
 */
typedef struct ndn_trust_schema_rule_component {
  /**
   * The component type.
   */
  uint32_t type;
  /**
   * The value which the rule component holds. Format of the buffer
   * depends on the trust schema rule component type.
   */
  uint8_t value[NDN_TRUST_SCHEMA_RULE_COMPONENT_BUFFER_SIZE];
  /**
   * The size of component value buffer.
   */
  uint32_t size;
} ndn_trust_schema_rule_component_t;

/**
 * The structure to represent the NDN Trust Schema rule.
 * This structure is memory expensive so please be careful when using it.
 */
typedef struct ndn_trust_schema_rule {
  /**
   * The array of schema components contained in this schema pattern (not including T and L)
   */
  ndn_trust_schema_rule_component_t components[NDN_TRUST_SCHEMA_RULE_COMPONENTS_SIZE];
  /**
   * The number of schema components
   */
  uint32_t components_size;
} ndn_trust_schema_rule_t;


/**
 * Appends a component to the end of a rule. This function will do memory copy.
 * @param name. Output. The rule to append to.
 * @param component. Input. The name component to append with.
 * @return 0 if there is no error.
 */
static inline int
ndn_trust_schema_rule_append_component(ndn_trust_schema_rule_t *rule, const ndn_trust_schema_rule_component_t* component)
{
  if (rule->components_size + 1 <= NDN_NAME_COMPONENTS_SIZE) {
    memcpy(rule->components + rule->components_size, component, sizeof(ndn_trust_schema_rule_component_t));
    rule->components_size++;
    return 0;
  }
  else
    return NDN_OVERSIZE;
}

/**
 * Init an NDN Trust Schema rule Component structure from caller supplied memory block.
 * The function will do memory copy
 * @param component. Output. The NDN Trust Schema rule Component structure to be inited.
 * @param type. Input. NDN Trust Schema rule Component Type to be set with.
 * @param value. Input. Memory block which holds the NDN Trust Schema Rule Component Value.
 * @param size. Input. Size of input block.
 * @return 0 if there is no error.
 */
static inline int
ndn_trust_schema_rule_component_from_buffer(ndn_trust_schema_rule_component_t* component, uint32_t type,
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
 * Probes a string to get its trust schema rule component type.
 * @param string. Input. String variable which will be probed for trust schema rule component type.
 * @param size. Input. Size of input string.
 * @return Returns the trust schema rule component type if there is no error and 
 *         the probing found a valid NDN trust schema rule component type.
 */
static inline int
_probe_trust_schema_rule_component_type(const char* string, uint32_t size)
{  
  /* printf("In _probe_trust_schema_rule_component_type, string passed in: %s\n", string); */

  int ret_val = -1;

  if (string[0] == '/') {
    if (re_match(_multiple_wildcard_rgxp, string) != TINY_REGEX_C_FAIL) {
      /* printf("In _probe_trust_schema_rule_component_type, found a match for %s.\n", _multiple_wildcard_rgxp); */
      return NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE;
    }
    else if (re_match(_single_wildcard_rgxp, string) != TINY_REGEX_C_FAIL) {
      /* printf("In _probe_trust_schema_rule_component_type, found a match for %s.\n", _single_wildcard_rgxp); */
      return NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT;
    }
    else if (re_match(_single_name_rgxp, string) != TINY_REGEX_C_FAIL) {
      /* printf("In _probe_trust_schema_rule_component_type, found a match for %s.\n", _single_name_rgxp); */
      return NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT;
    }
    else if (re_match(_subpattern_match_rgxp, string) != TINY_REGEX_C_FAIL) {
      /* printf("In _probe_trust_schema_rule_component_type, found a match for %s.\n", _subpattern_match_rgxp); */
      return NDN_TRUST_SCHEMA_SUBPATTERN_MATCH;
    }
    else if (re_match(_function_ref_rgxp, string) != TINY_REGEX_C_FAIL) {
      /* printf("In _probe_trust_schema_rule_component_type, found a match for %s.\n", _function_ref_rgxp); */
      return NDN_TRUST_SCHEMA_FUNCTION_REF;
    }
  }
  else {
    if (re_match(_rule_ref_rgxp, string) != TINY_REGEX_C_FAIL) {
      /* printf("In _probe_trust_schema_rule_component_type, found a match for %s.\n", _rule_ref_rgxp); */
      return NDN_TRUST_SCHEMA_RULE_REF;
    }
  }

  /* printf("In _probe_trust_schema_rule_component_type, found an unrecognizable rule component.\n"); */
  return NDN_TRUST_SCHEMA_RULE_COMPONENT_UNRECOGNIZED_TYPE;

}

/**
 * Init an NDN Trust Schema Rule Component structure from string. Please include the last byte of the string,
 * which is "\0". The function will do memory copy.
 * @param component. Output. The NDN Trust Schema Rule Component structure to be inited.
 * @param string. Input. String variable which NDN Trust Schema rule component initing from.
 * @param size. Input. Size of input string.
 * @return 0 if there is no error.
 */
static inline int
ndn_trust_schema_rule_component_from_string(ndn_trust_schema_rule_component_t* component, const char* string, uint32_t size)
{

  char function_msg_prefix[] = "In ndn_trust_schema_rule_component_from_string, ";
  
  printf("In ndn_trust_schema_rule_component_from_string, string passed in: %s\n", string);
  
  int ret_val = -1;
  
  uint32_t string_size = string[size - 1] == '\0' ? size-1 : size;

  int type = _probe_trust_schema_rule_component_type(string, size);

  switch (type) {
  case NDN_TRUST_SCHEMA_SINGLE_NAME_COMPONENT:
    printf("%sgot a single name component.\n", function_msg_prefix);
    break;
  case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT:
    printf("%sgot a wildcard name component.\n", function_msg_prefix);
    break;
  case NDN_TRUST_SCHEMA_WILDCARD_NAME_COMPONENT_SEQUENCE:
    printf("%sgot a wildcard name component sequence.\n", function_msg_prefix);
    break;
  case NDN_TRUST_SCHEMA_SUBPATTERN_MATCH:
    printf("%sgot a subpattern match.\n", function_msg_prefix);
    printf("%ssubpattern query found inside of subpattern match: %.*s\n", function_msg_prefix, size-4, string + 2);
    break;
  case NDN_TRUST_SCHEMA_FUNCTION_REF:
    printf("%sgot a function reference.\n", function_msg_prefix);
    printf("%sname of function being referenced: %.*s\n", function_msg_prefix, size - 4, string + 2);
    break;
  case NDN_TRUST_SCHEMA_RULE_REF:
    printf("%sgot a rule reference.\n", function_msg_prefix);
    ret_val = re_match(_rule_ref_args_rgxp, string);
    if (ret_val == TINY_REGEX_C_FAIL) {
      return NDN_TRUST_SCHEMA_RULE_COMPONENT_PARSING_ERROR;
    }
    printf("%sstarting index of rule reference's arguments: %d\n", function_msg_prefix, ret_val);
    printf("%srule reference's arguments: %.*s\n", function_msg_prefix, size - 3 - ret_val, string + ret_val + 1);
    break;
  default:
    return NDN_TRUST_SCHEMA_RULE_COMPONENT_PARSING_ERROR;
  }

  printf ("\n");
  
}

/**
 * Init an NDN Trust Schema rule from a string. This function will do memory copy and
 * only support regular string; not support URI currently.
 * @param name. Output. The NDN Trust Schema rule to be inited.
 * @param string. Input. The string from which the NDN Trust Schema rule is inited.
 * @param size. Input. Size of the input string.
 * @return 0 if there is no error.
 */
int
ndn_trust_schema_rule_from_string(ndn_trust_schema_rule_t* pattern, const char* string, uint32_t size);

#endif // NDN_TRUST_SCHEMA_H
