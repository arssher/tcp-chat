CFLAGS = -std=c++11 -g -Wall -ansi -pedantic
CC = g++

all: chatserv chatclient

chatserv:
	$(CC) $(CFLAGS) -o $@ server.cpp

chatclient:
	$(CC) $(CFLAGS) -o $@ client.cpp

.PHONY: clean
clean:
	- rm chatserv chatclient
