---

## The includes

```c
#include <linux/bpf.h>
```

The foundational BPF header. Defines the core types and constants the BPF subsystem exposes to programs: `struct xdp_md` (your context), `XDP_PASS`/`XDP_DROP`/`XDP_TX` (return values), `BPF_MAP_TYPE_*` (map types), and the `__u8`/`__u16`/`__u32`/`__u64` fixed-width integer typedefs that BPF code uses instead of `int`/`long` (because `int` size is platform-dependent — in kernel code you always want explicit widths).

```c
#include <linux/if_ether.h>
```

Defines `struct ethhdr` and EtherType constants. The Ethernet header is the outermost wrapper on every packet on a wired or WiFi network. `ETH_P_IP` = `0x0800` means the payload is IPv4. You need this header to know the layout of those first 14 bytes of every packet.

```c
#include <linux/ip.h>
```

Defines `struct iphdr`. The IPv4 header follows immediately after the Ethernet header. This struct gives you named fields for source IP (`saddr`), destination IP (`daddr`), protocol (`protocol`), TTL, total length, and others. Without this header you'd be reading raw byte offsets — error-prone and unreadable.

```c
#include <bpf/bpf_helpers.h>
```

Defines the BPF helper function declarations — `bpf_printk()`, `bpf_map_lookup_elem()`, `bpf_xdp_adjust_head()`, and about 200 others. These are not real function calls in the traditional sense. Each one compiles to a `call 0xN` instruction (like `call 0x6` you saw in the disassembly) — a dispatch into the kernel's helper table. Without this header, those functions don't exist in your compilation unit.

```c
#include <bpf/bpf_endian.h>
```

Defines `bpf_ntohs()` and `bpf_ntohl()`. Network byte order is big-endian. x86 is little-endian. If you read `eth->h_proto` on an x86 machine without byte-swapping, the bytes are reversed — `0x0800` (IPv4) reads as `0x0008`. This header provides byte-swap helpers that compile to native BPF byte-swap instructions (`bswap`) rather than libc calls (which you can't use in BPF anyway).

---

## The function signature

```c
SEC("xdp")
int packet_inspect(struct xdp_md *ctx)
```

`SEC("xdp")` places this function in the ELF section named `xdp`. libbpf reads that section name to determine two things: the program type (`BPF_PROG_TYPE_XDP`) and the expected context struct. The verifier uses the program type to decide which helpers are permitted — `bpf_printk` is available to XDP programs, but some helpers like `bpf_get_socket_cookie` are not.

The return type is `int` because XDP return values (`XDP_PASS` = 2, `XDP_DROP` = 1, etc.) are integers. The function takes exactly one argument — the context pointer. You cannot add more arguments. The BPF calling convention on entry is: r1 holds the context pointer, everything else is undefined. The verifier enforces this — it knows the program type and initializes its model of r1 accordingly before simulating your first instruction.

`struct xdp_md` has exactly these fields:

```c
struct xdp_md {
    __u32 data;           // offset to packet start
    __u32 data_end;       // offset to packet end
    __u32 data_meta;      // offset to metadata area (before data)
    __u32 ingress_ifindex; // interface the packet arrived on
    __u32 rx_queue_index; // RX queue index
    __u32 egress_ifindex; // for XDP_REDIRECT
};
```

You saw all six fields in the BTF dump earlier. `data` and `data_end` are what you need for packet parsing. `ingress_ifindex` becomes useful in Phase 5 when you need to know which node interface a packet arrived on.

---

## The pointer setup

```c
void *data     = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;
```

This is the most important boilerplate in any XDP program. Understand it deeply.

`ctx->data` is a `__u32` — a 32-bit unsigned integer holding a memory offset. It is not a pointer. The XDP framework stores packet locations as offsets rather than raw pointers for technical reasons related to how the DMA buffer and page system work. To use it for packet parsing you need to convert it to a pointer.

The cast `(void *)(long)ctx->data` does this in two steps. First `(long)` widens the 32-bit value to a 64-bit signed integer — this zero-extends it without ambiguity. Then `(void *)` converts that integer to a pointer. The intermediate `long` step matters because going directly `(void *)(__u32)` is a narrowing cast on a 64-bit system and can generate verifier warnings — the verifier's type system is strict about integer-to-pointer conversions and the two-step cast is the canonical safe form.

After these two lines, `data` and `data_end` are `void *` pointers that the verifier tracks as `PTR_TO_PACKET` and `PTR_TO_PACKET_END` respectively. These are special pointer types in the verifier's type system — distinct from `PTR_TO_MAP_VALUE` or `PTR_TO_STACK`. The bounds checking rules only apply when you're comparing a `PTR_TO_PACKET` against `PTR_TO_PACKET_END`. If you accidentally compared against a plain integer, the verifier would reject it.

---

## The Ethernet header parse

```c
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
```

`struct ethhdr *eth = data` — cast the start of the packet to an Ethernet header pointer. No offset needed because Ethernet is always the outermost layer. `struct ethhdr` is 14 bytes: 6 bytes destination MAC, 6 bytes source MAC, 2 bytes EtherType.

`(void *)(eth + 1)` — this is pointer arithmetic on a typed pointer. In C, adding 1 to a pointer of type `T *` advances by `sizeof(T)` bytes. So `eth + 1` is `data + sizeof(struct ethhdr)` = `data + 14`. Casting to `void *` makes the comparison type-safe for the verifier.

What this expression means semantically: "the address of the first byte after the Ethernet header." If that address is greater than `data_end`, the packet buffer doesn't contain a complete Ethernet header — it's truncated. You return `XDP_PASS` to let the kernel handle it normally (or drop it — your choice, but `XDP_PASS` is the safe default).

Why `eth + 1` instead of `data + 14`? Because `eth + 1` is self-documenting and stays correct if `struct ethhdr`'s definition ever changes. It also clearly expresses intent: "one full header past the start." You'll use this exact pattern — `(void *)(header_ptr + 1) > data_end` — for every protocol header you parse. It becomes muscle memory.

After this check passes, the verifier knows: for any code path that reaches the next line, `data` through `data + 13` is valid memory. It will now permit you to read `eth->h_proto`, `eth->h_dest`, `eth->h_source`. Before the check, any such read would be rejected.

---

## The EtherType check

```c
if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return XDP_PASS;
```

`eth->h_proto` is the EtherType field — 2 bytes at offset 12 of the Ethernet header, stored in network byte order (big-endian). `bpf_ntohs()` converts from network to host byte order. `ETH_P_IP` is `0x0800`.

This filter is essential. Your XDP program fires on every incoming packet — ARP, IPv6, VLAN-tagged frames, LLDP, everything. If you skip this check and try to parse an ARP packet as if it were IPv4, you'd be reading the ARP hardware type field as if it were an IP source address. The data would be garbage. Worse, the verifier doesn't know the EtherType at compile time, so it can't protect you — it only enforces memory bounds, not semantic correctness.

Other EtherType values you'll encounter in Phase 5:

```c
ETH_P_IPV6  = 0x86DD   // IPv6
ETH_P_ARP   = 0x0806   // ARP
ETH_P_8021Q = 0x8100   // VLAN tagged frame
```

---

## The IP header parse

```c
struct iphdr *ip = (void *)(eth + 1);
if ((void *)(ip + 1) > data_end)
    return XDP_PASS;
```

`(void *)(eth + 1)` — the IPv4 header starts immediately after the Ethernet header. Same pointer arithmetic as before: `eth + 1` = `data + 14`. We already know from the previous bounds check that `data + 13` is valid, but the verifier requires a fresh bounds check for each new header because `struct iphdr` extends further — it's 20 bytes minimum.

`(void *)(ip + 1) > data_end` — checks that `data + 14 + sizeof(struct iphdr)` = `data + 34` is within bounds. After this check the verifier permits access to all fixed fields of `struct iphdr`: `saddr`, `daddr`, `protocol`, `ttl`, `tot_len`, `ihl`, etc.

One subtlety: `struct iphdr` represents the fixed 20-byte IPv4 header. The IP header can be longer if IP options are present — `ihl` (internet header length) tells you the actual length in 32-bit words. For basic packet parsing you ignore options and treat the fixed header as the entire header. If you need to parse TCP/UDP headers that follow, you'd calculate the actual IP header end as `(void *)ip + (ip->ihl * 4)` and do another bounds check against that.

---

## The print

```c
bpf_printk("src: %x  dst: %x  proto: %d\n",
           bpf_ntohl(ip->saddr),
           bpf_ntohl(ip->daddr),
           ip->protocol);
```

`ip->saddr` and `ip->daddr` are `__be32` — 32-bit values in big-endian (network) byte order. `bpf_ntohl()` converts to host byte order so the hex representation is human-readable. The IP `192.168.4.42` in network byte order is stored as `0x2a04a8c0` — reversed. After `bpf_ntohl()` it's `0xc0a8042a`, which reads left to right as `c0.a8.04.2a` = `192.168.4.42`.

`ip->protocol` is a single byte — no byte swapping needed. Protocol 1 = ICMP, 6 = TCP, 17 = UDP. You saw proto 1 in your output — that's ping.

`bpf_printk` accepts a maximum of 3 format arguments. This is a kernel-level restriction on `bpf_trace_printk`. If you need more fields, you either make multiple calls or use a BPF map to pass structured data to userspace — which is exactly what we'll do next with the map-based approach.

---

## The return

```c
return XDP_PASS;
```

Every code path in your program must return a valid XDP action. The verifier enforces this — if any code path reaches the end of the function without a return, the program is rejected. `XDP_PASS` tells the kernel to continue processing this packet through the normal network stack. The packet goes up through the TC layer, through netfilter, and eventually to a socket. Nothing you did in this program affects the packet's content or delivery — you were a pure observer.

When you write Phase 5's XDP load balancer, this line becomes `return XDP_TX` (to bounce the DNAT'd packet back out the same interface) or `XDP_REDIRECT` (to forward it to a different interface). The packet parsing logic is identical — only the return value and the header rewriting before it changes.

---