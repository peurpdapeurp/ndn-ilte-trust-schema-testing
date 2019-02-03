
SOURCES_C := \
	../ndn-lite/encode/name.c \
	../ndn-lite/encode/name-component.c \
	tiny-regex-c/re.c \
	ndn_re.c \

default:
	gcc -o schematized_trust_test main.c $(SOURCES_C)

clean:
	- rm schematized_trust_test
