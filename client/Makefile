CC = gcc
HEADERS = madlib/Caps.h
EXTRA_CFLAGS= -I$(PWD)/madlib

default:
	make injector

client.o: client.c $(HEADERS)
	gcc -c client.c

injector: client.o madlib/libCaps_madlib.a
	gcc -lm -o injector client.o -L. madlib/Caps_madlib.a

clean:
	-rm -f client.o
	-rm -f injector
