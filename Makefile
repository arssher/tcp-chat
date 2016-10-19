CFLAGS = -std=c++11 -g -Wall -pedantic -Werror=vla
CC = g++

all: chatserv chatclient

chatserv:
	$(CC) $(CFLAGS) -o $@ server.c

chatclient:
	$(CC) $(CFLAGS) -o $@ client.c

.PHONY: clean
clean:
	- rm chatserv chatclient
