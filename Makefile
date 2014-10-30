# -*- coding: utf-8-unix; -*-


PROG=pcap2zmq
OBJS=pcap2zmq.o utils.o


default: $(PROG)

# we need zmq v3. Defian 6.0 squeezy needs install this library separately
ZMQ_DIR = /usr/local/lib/zeromq-3.2.2
# PCAP_DIR = /usr/local/lib/libpcap-1.1.1

CINCFLAGS =
CINCFLAGS += -I$(ZMQ_DIR)/include 
# CINCFLAGS += -I$(PCAP_DIR)/include

COPTFLAGS = -g -O2 -std=gnu99 -Werror -pedantic -Wall -Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes
CFLAGS = $(CINCFLAGS) $(COPTFLAGS)

LDLIBFLAGS =
LDLIBFLAGS += -L$(ZMQ_DIR)/lib
# LDLIBFLAGS += -L$(PCAP_DIR)/lib 

LDFLAGS = $(LDLIBFLAGS) -lzmq -lpcap


-include $(OBJS:.o=.d)


%.o: %.c
	gcc -c $(CFLAGS) $*.c -o $*.o
	gcc -MM $(CFLAGS) $*.c > $*.d


$(PROG): $(OBJS)
	gcc $(LDFLAGS) -o $(PROG) $(OBJS)

clean:
	rm -f $(PROG) *.o *.d *~ core core.*
