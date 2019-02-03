
#ifndef NDN_RE_H
#define NDN_RE_H

#include "../ndn-lite/encode/name.h"

// this prototype NDN trust schema regex implementation is built on top of the tiny-regex-c library,
// and implements the NDN trust schema regex patterns as described in Table 1 of
// https://named-data.net/wp-content/uploads/2015/06/ndn-0030-2-trust-schema.pdf

int ndn_re_match(const ndn_name_t *pattern, const ndn_name_t *name);

#endif // NDN_RE_H
