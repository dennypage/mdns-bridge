#CC=clang
#CFLAGS=-Wall -Wextra -g -O2

all: mdns-bridge

all_objects = main.o config.o interface.o filter.o bridge.o socket.o dns_decode.o dns_encode.o
dns_objects = dns_decode.o dns_encode.o

$(all_objects): common.h
$(dns_objects): dns.h

mdns-bridge: $(all_objects)
	$(CC) -o mdns-bridge -pthread $(all_objects)

.PHONY: clean
clean:
	rm -f mdns-bridge $(all_objects)
