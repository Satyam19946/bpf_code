CLANG   = clang
CC      = gcc
CFLAGS  = -O2 -g -target bpf -D__TARGET_ARCH_x86 \
          -I/usr/include/x86_64-linux-gnu
LDFLAGS = -lbpf

# list of programs — add a line here for each new one
PROGRAMS = hello packet_inspect packet_counter connection_tracker mytcpdump xdp_dnat

.PHONY: all clean $(PROGRAMS)

all: $(PROGRAMS)

hello:
	$(CLANG) $(CFLAGS) -c hello/hello.bpf.c -o hello/hello.bpf.o
	$(CC) -O2 -g -o hello/hello hello/hello_loader.c $(LDFLAGS)

packet_inspect:
	$(CLANG) $(CFLAGS) -c packet_inspect/packet_inspect.bpf.c \
		-o packet_inspect/packet_inspect.bpf.o
	$(CC) -O2 -g -o packet_inspect/packet_inspect_loader\
		packet_inspect/packet_inspect_loader.c $(LDFLAGS)

packet_counter:
	$(CLANG) $(CFLAGS) -c packet_counter/packet_counter.bpf.c \
		-o packet_counter/packet_counter.bpf.o
	$(CC) -O2 -g -o packet_counter/packet_counter_loader \
		packet_counter/packet_counter_loader.c $(LDFLAGS)

connection_tracker:
	$(CLANG) $(CFLAGS) -c connection_tracker/connection_tracker.bpf.c \
		-o connection_tracker/connection_tracker.bpf.o
	$(CC) -O2 -g -o connection_tracker/connection_tracker_loader \
		connection_tracker/connection_tracker_loader.c $(LDFLAGS)

mytcpdump:
	$(CLANG) $(CFLAGS) -I mytcpdump \
		-c mytcpdump/mytcpdump.bpf.c -o mytcpdump/mytcpdump.bpf.o
	$(CC) -O2 -g -I mytcpdump \
		-o mytcpdump/mytcpdump_loader \
		mytcpdump/mytcpdump_loader.c $(LDFLAGS)

xdp_dnat:
	$(CLANG) $(CFLAGS) -I xdp_dnat \
		-c xdp_dnat/xdp_dnat.bpf.c -o xdp_dnat/xdp_dnat.bpf.o
	$(CC) -O2 -g -I xdp_dnat \
		-o xdp_dnat/xdp_dnat_loader \
		xdp_dnat/xdp_dnat_loader.c $(LDFLAGS)

clean:
	find . -name "*.bpf.o" -delete
	find . -name "*_loader" -delete