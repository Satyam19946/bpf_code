#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>


static volatile int keep_running = 1;

void handle_sig(int sig)
{
    keep_running = 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <interface>\n", argv[0]);
        return 1;
    }

    // 1. Open and load the BPF object file
    struct bpf_object *obj = bpf_object__open("hello.bpf.o");
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)){
        fprintf(stderr, "failed to load BPF object\n");
        return 1;
    }

    // 2. find the program by section name
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "hello");
    if (!prog){
        fprintf(stderr, "failed to find BPF program\n");
        return 1;
    } 

    // 3. Get the interface index
    unsigned int ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "unknown interface: %s\n", argv[1]);
        return 1;
    }

    // 4. attach the XDP program to the interface
    int prog_fd = bpf_program__fd(prog);
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
        fprintf(stderr, "failed to attach XDP program\n");
        return 1;
    }

    // 5. keep running until sgnal interrupt (ctrl+c)
    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);
    while (keep_running){
        sleep(1);
    }

    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);

    printf("\ndetached\n");
    return 0;
}