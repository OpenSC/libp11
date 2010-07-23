CFLAGS=-O2 -g $(shell pkg-config --cflags libp11) $(shell pkg-config --cflags libcrypto)
LDFLAGS=$(shell pkg-config --libs libp11) $(shell pkg-config --libs libcrypto)

all: auth decrypt getrandom

clean:
	rm auth decrypt getrandom
