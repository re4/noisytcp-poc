# noisytcp - C trigger for CVE-2026-99288 (NoisyTCP)
#
#   make            build ./noisytcp
#   make debug      -O0 -g build
#   make clean

CC      ?= cc
CFLAGS  ?= -O2 -g
WARN     = -Wall -Wextra -Wshadow -Wno-unused-parameter
LDLIBS   = -pthread

all: noisytcp

noisytcp: noisytcp.c
	$(CC) $(CFLAGS) $(WARN) -std=c11 -o $@ noisytcp.c $(LDLIBS)

debug: noisytcp.c
	$(CC) -O0 -g3 $(WARN) -std=c11 -o noisytcp noisytcp.c $(LDLIBS)

clean:
	rm -f noisytcp

.PHONY: all debug clean
