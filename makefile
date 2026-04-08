CLANG   = clang
CC      = gcc
CFLAGS  = -O2 -g -target bpf -D__TARGET_ARCH_x86 \
          -I/usr/include/x86_64-linux-gnu
LDFLAGS = -lbpf

# list of programs — add a line here for each new one
PROGRAMS = hello packet_inspect

.PHONY: all clean $(PROGRAMS)

all: $(PROGRAMS)

hello:
	$(CLANG) $(CFLAGS) -c hello/hello.bpf.c -o hello/hello.bpf.o
	$(CC) -O2 -g -o hello/hello hello/hello_user.c $(LDFLAGS)

packet_inspect:
	$(CLANG) $(CFLAGS) -c packet_inspect/packet_inspect.bpf.c \
		-o packet_inspect/packet_inspect.bpf.o
	$(CC) -O2 -g -o packet_inspect/packet_inspect_user \
		packet_inspect/packet_inspect_user.c $(LDFLAGS)

clean:
	find . -name "*.bpf.o" -delete
	find . -name "*_user" -delete
	rm -f hello/hello