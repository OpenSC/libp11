CFLAGS=-O2 -g $(shell pkg-config --cflags libp11)
LDFLAGS=$(shell pkg-config --libs libp11)

all: auth decrypt getrandom

clean:
	rm auth decrypt getrandom
