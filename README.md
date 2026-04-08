# bpf_code

A collection of BPF programs written in C as part of a progressive learning
project building toward a custom eBPF-based CNI for Kubernetes. Each program
is self-contained and introduces one new concept on top of the previous.

## Environment

- OS: Ubuntu 24.04 LTS
- Kernel: 6.8.x
- Toolchain: clang 18, libbpf, bpftool, llvm-objdump

## Toolchain installation

```bash
sudo apt install -y clang llvm libbpf-dev \
  linux-headers-$(uname -r) \
  linux-tools-$(uname -r) \
  linux-tools-common \
  bpftool
```

## Repository structure

```
bpf_code/
├── Makefile
├── hello/
│   ├── hello.bpf.c          # kernel side — XDP program, bpf_printk to trace_pipe
│   └── hello_loader.c       # userspace loader — attach to interface
├── packet_inspect/
│   ├── packet_inspect.bpf.c # parse Ethernet + IPv4, print src/dst/proto
│   └── packet_inspect_loader.c
├── packet_counter/
│   ├── packet_counter.bpf.c # BPF_MAP_TYPE_HASH counting packets per protocol
│   └── packet_counter_loader.c
├── connection_tracker/
│   ├── connection_tracker.bpf.c  # struct map keys, per-connection packet+byte counts
│   └── connection_tracker_loader.c
├── mytcpdump/
│   ├── mytcpdump.h          # shared struct packet_event (kernel + userspace)
│   ├── mytcpdump.bpf.c      # BPF_MAP_TYPE_RINGBUF, TCP/UDP port parsing
│   └── mytcpdump_loader.c   # ring_buffer__poll, event-driven output
└── xdp_dnat/
    ├── xdp_dnat.h           # shared structs: service_key, backend
    ├── xdp_dnat.bpf.c       # map lookup, IP/port rewrite, checksum update, bpf_redirect
    └── xdp_dnat_loader.c    # pre-populates service_map with a test VIP entry
```

## Building

```bash
# build all programs
make

# build a specific program
make hello
make packet_inspect
make packet_counter
make connection_tracker
make mytcpdump
make xdp_dnat

# clean build artifacts
make clean
```

## Programs

### hello

The entry point. An XDP program that calls `bpf_printk` on every incoming
packet. Demonstrates the two-file structure, ELF sections, and the
compile → load → attach → observe loop.

```bash
sudo ./hello/hello <interface>
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**Concepts:** `SEC("xdp")`, `bpf_printk`, `XDP_PASS`, `GPL` license section,
`bpf_object__open/load`, `bpf_xdp_attach/detach`.

---

### packet_inspect

Parses Ethernet and IPv4 headers and prints source IP, destination IP, and
protocol for every IPv4 packet. Introduces the mandatory bounds checking
pattern the verifier enforces.

```bash
sudo ./packet_inspect/packet_inspect_loader <interface>
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**Concepts:** `struct ethhdr`, `struct iphdr`, `(void *)(ptr + 1) > data_end`
bounds check pattern, `PTR_TO_PACKET` vs `PTR_TO_PACKET_END`, `bpf_ntohs`,
`__be32` vs `__u32`.

---

### packet_counter

Counts packets per IP protocol number using a `BPF_MAP_TYPE_HASH` map. The
kernel side increments atomically; the userspace side polls the map every 2
seconds and prints counts.

```bash
sudo ./packet_counter/packet_counter_loader <interface>
```

**Concepts:** BTF-based map declaration (`__uint`, `__type` macros),
`bpf_map_lookup_elem` NULL check, `__sync_fetch_and_add` for concurrent
counters, `BPF_NOEXIST` for safe concurrent insert,
`bpf_map_get_next_key` iteration from userspace.

---

### connection_tracker

Tracks per-connection packet and byte counts using a struct key
`{src_ip, dst_ip, proto}` and a struct value `{packets, bytes}`.
Introduces the padding discipline required for struct map keys.

```bash
sudo ./connection_tracker/connection_tracker_loader <interface>
```

**Concepts:** Struct map keys — implicit compiler padding causes silent lookup
failures (all bytes of the key are hashed including padding). Fix: explicit
`__u8 pad[]` fields + `struct key = {}` zero initializer. `__be32` semantic
annotation. `ip->tot_len` vs `data_end - data` for packet length.
Stack pointer rule: map key/value pointers must be `PTR_TO_STACK`,
never `PTR_TO_PACKET`.

---

### mytcpdump

A tcpdump-like program that streams structured packet events to userspace in
real time using `BPF_MAP_TYPE_RINGBUF`. Parses Ethernet, IPv4, TCP, and UDP.
Outputs protocol, source IP:port, destination IP:port, and length.

```bash
sudo ./mytcpdump/mytcpdump_loader <interface>
```

**Concepts:** `BPF_MAP_TYPE_RINGBUF` — single producer (kernel), single
consumer (userspace), zero-copy via `mmap`. `bpf_ringbuf_reserve` reserves a
typed slot; `bpf_ringbuf_submit` makes it visible; `bpf_ringbuf_discard` if
you decide not to emit. `ring_buffer__new` calls `mmap` twice — consumer
metadata page and data pages. `ring_buffer__poll` uses `epoll_wait` internally.
Shared `.h` header for struct definitions used by both kernel and userspace.
`ip->ihl * 4` for variable-length IP header. `goto submit` for committed
ringbuf slots. `linux/in.h` for `IPPROTO_TCP`/`IPPROTO_UDP` in kernel-side code.

---

### xdp_dnat

A Destination NAT (DNAT) load balancer. Intercepts packets at XDP, looks up
the destination IP:port in a hash map, rewrites the destination to a backend
IP:port, updates IP and TCP/UDP checksums, and redirects the packet to the
correct interface using `bpf_redirect`.

This is the kernel-side core of a Kubernetes Service load balancer — the same
mechanism Cilium uses for ClusterIP routing, without iptables or conntrack.

```bash
# pre-populates map: 10.96.0.10:80 TCP → 10.244.1.5:8080
sudo ./xdp_dnat/xdp_dnat_loader <interface>
```

**Concepts:** Map lookup as a routing decision. Incremental checksum update
(`csum_update`) — O(1) fixup without re-checksumming the entire header.
IP checksum covers IP header only; TCP/UDP checksum also covers the
pseudo-header (src IP, dst IP, proto, length) so an IP address change
requires fixing both checksums. `bpf_redirect(ifindex, 0)` to send
a packet to a specific interface. Ethernet header rewrite required before
redirecting across interfaces — the frame must have valid MACs for the
destination interface. `XDP_TX` bounces back out the same interface;
`bpf_redirect` sends to a different one. XDP-redirected packets are
invisible to tcpdump — capture on the receiving interface instead.

---

## Key BPF programming rules learned

**Bounds checking** — every packet field access must be preceded by
`if ((void *)(ptr + 1) > data_end) return XDP_PASS`. The verifier enforces
this statically. No check = program rejected at load time.

**NULL check after lookup** — `bpf_map_lookup_elem` returns
`PTR_TO_MAP_VALUE_OR_NULL`. The verifier rejects any dereference without
a prior NULL check on every code path.

**Stack pointer rule** — map key and value pointers must be `PTR_TO_STACK`
or `PTR_TO_MAP_VALUE`. Never pass `PTR_TO_PACKET` directly as a key pointer.
Copy packet fields to local stack variables first.

**Struct key padding** — the map hashes all bytes of the key struct including
implicit compiler padding. Uninitialized padding = silent lookup failures.
Always use explicit pad fields and `struct key = {}` zero initializer.

**Atomic counters** — use `__sync_fetch_and_add` for counters in regular
hash maps. Multiple CPU cores run XDP programs concurrently.

**No libc in kernel-side BPF** — use `bpf_ntohs`/`bpf_ntohl` not
`ntohs`/`ntohl`. Use `__builtin_memset` not `memset`. Use `<linux/in.h>`
not `<netinet/in.h>`.

**Uninitialised variables** — the verifier tracks register state across
all code paths. A variable that is not initialized on every path reaching
its use will be rejected with `!read_ok`. Initialize at declaration.

**Ringbuf commit rule** — once `bpf_ringbuf_reserve` succeeds you must
call either `bpf_ringbuf_submit` or `bpf_ringbuf_discard`. Leaving a
slot neither submitted nor discarded stalls the ring permanently.

## Debugging tools

```bash
# see loaded BPF programs
sudo bpftool prog list

# disassemble BPF bytecode — cross-reference with verifier errors
llvm-objdump -d <program>.bpf.o

# dump BTF type information
bpftool btf dump file <program>.bpf.o

# dump map contents (with BTF — shows field names)
sudo bpftool map dump name <map_name>

# verbose verifier output on load failure
sudo bpftool prog load <program>.bpf.o /sys/fs/bpf/<name> 2>&1
sudo rm /sys/fs/bpf/<name>

# watch BPF debug output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## What comes next

These programs are the foundation for Phase 5 of the
[k8s-ebpf-lab](https://github.com/satyam19946/k8s-ebpf-lab) project —
building a custom eBPF CNI for Kubernetes from scratch. The `xdp_dnat`
program becomes the service load balancer. A TC egress SNAT program
handles the return path. A CNI binary handles pod lifecycle. A control
plane daemon keeps the maps in sync with the Kubernetes API.