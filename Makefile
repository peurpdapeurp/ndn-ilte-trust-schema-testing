
SOURCES_C := \
	../ndn-lite/encode/name.c \
	../ndn-lite/encode/name-component.c \
	tiny-regex-c/re.c \
	ndn-trust-schema.c \
	ndn-trust-schema-rule.c \
	ndn-trust-schema-pattern.c \
	ndn-trust-schema-pattern-component.c

default:
	gcc -o schematized_trust_test main.c $(SOURCES_C)

clean:
	- rm schematized_trust_test
