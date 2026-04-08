CLANG = clang
CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86

all: hello.bpf.o hello

hello.bpf.o: hello.bpf.c
	$(CLANG) $(CFLAGS) \
		-I/usr/include/x86_64-linux-gnu \
		-c hello.bpf.c -o hello.bpf.o

hello: hello.c
	gcc -O2 -o hello hello.c -lbpf

clean:
	rm -f hello.bpf.o hello