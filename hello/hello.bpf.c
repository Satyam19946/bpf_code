#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int hello(struct xdp_md *ctx)
{
    bpf_printk("hello world\n");
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";