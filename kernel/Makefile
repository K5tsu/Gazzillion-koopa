CC = gcc
EXTRA_CFLAGS=-I$(PWD)/include -I$(PWD)/src -I$(PWD)/lib
obj-m += koopa.o
koopa-objs :=  main.o src/ftrace_manager.o src/creds_manager.o src/hookers.o src/utils.o src/netfilter_manager.o

all:
	make -C /madlib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /madlib/modules/$(shell uname -r)/build M=$(PWD) clean
