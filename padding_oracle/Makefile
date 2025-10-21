CC=gcc
CFLAGS=-O2 -Wall
OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl)
CFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS += -L$(OPENSSL_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib
LDLIBS=-lcrypto

all: victim gen_target attacker

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

gen_target: gen_target.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

attacker: attacker_skeleton.c
	$(CC) $(CFLAGS) -o $@ $<

