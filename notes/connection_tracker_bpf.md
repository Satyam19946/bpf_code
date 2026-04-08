Here are the notes for `connection_tracker.bpf.c` — the key concepts worth retaining as a BPF programmer.

---

## `__be32` vs `__u32` — semantic type annotation

`__be32` `example - (__be32  src_ip;)` means "32-bit value stored in big-endian (network) byte order." At the machine level it is identical to `__u32` — same bits, same size. The distinction is purely semantic: it tells you, the compiler's static analyzer (sparse), and anyone reading the code that this value must not be used in arithmetic or comparisons without first converting with `bpf_ntohl`. Use `__be32` for IP addresses and port numbers that you store directly from packet headers and look up directly from packet headers — no conversion on the hot path.

## The padding rule — the most important rule for struct map keys

The BPF map uses the key as raw bytes for hashing and comparison — every byte, including compiler-inserted padding. If your struct has implicit padding (alignment gaps the compiler fills silently), those bytes contain stack garbage. Two lookups with identical field values but different padding bytes hash to different buckets and never match. You silently create a new entry on every packet instead of finding the existing one. This failure mode produces no error — the program loads, runs, and produces wrong results.

The struct without explicit padding:

```c
struct conn_key {
    __be32 src_ip;   // bytes 0-3
    __be32 dst_ip;   // bytes 4-7
    __u8   proto;    // byte 8
    // 3 bytes of implicit compiler padding here — UNINITIALIZED
};
```

The correct version:

```c
struct conn_key {
    __be32 src_ip;
    __be32 dst_ip;
    __u8   proto;
    __u8   pad[3];   // explicit — controlled by you
};
```

Combined with the zero initializer:

```c
struct conn_key key = {};   // zeroes ALL bytes including pad
key.src_ip = ip->saddr;
key.dst_ip = ip->daddr;
key.proto  = ip->protocol;
```

The `= {}` must happen before field assignments. Field assignments only touch named fields — they leave pad bytes untouched. The rule: **every byte of a struct map key must be deterministic. Explicit pad + zero initializer is the standard pattern.**

The alternative that also works:

```c
struct conn_key key;
__builtin_memset(&key, 0, sizeof(key));   // not memset — no libc in BPF
```

`__builtin_memset` is the BPF-safe version. Same effect, slightly more verbose.

## Stack pointer rule for map helpers

`bpf_map_lookup_elem` and `bpf_map_update_elem` require key and value pointers to be `PTR_TO_STACK` or `PTR_TO_MAP_VALUE`. They cannot be `PTR_TO_PACKET`. You cannot pass `&ip->saddr` directly as a map key — it's a pointer into the packet buffer. Always copy fields to a local stack struct first:

```c
__u8 proto = ip->protocol;                         // stack variable
__u64 *count = bpf_map_lookup_elem(&map, &proto);  // PTR_TO_STACK — valid
```

This is a verifier rule, not a runtime behavior. The program is rejected at load time if you violate it.

## `ip->tot_len` vs `data_end - data` for packet size

Use `bpf_ntohs(ip->tot_len)` to get the IP packet length, not `data_end - data`. The DMA buffer can have trailing hardware padding bytes beyond the actual IP packet — `data_end - data` counts those and inflates your byte total. `tot_len` is what the IP header declares as the true payload length. Convert with `bpf_ntohs` because it's stored in network byte order.

## `BPF_NOEXIST` for concurrent map inserts

When `bpf_map_lookup_elem` returns NULL (first packet for this key), use `BPF_NOEXIST` for the insert:

```c
__u64 init = 1;
bpf_map_update_elem(&conn_table, &key, &init, BPF_NOEXIST);
```

Between the lookup returning NULL and the update executing, another CPU core processing a different packet with the same key could have inserted it first. `BPF_NOEXIST` makes your insert a safe no-op in that race — the other core's entry stands. `BPF_ANY` would overwrite it with 1, losing that core's count.

## `__sync_fetch_and_add` for concurrent counters

Multiple CPU cores run your XDP program simultaneously. Without atomics, concurrent `*count += 1` operations lose updates — both cores read the same value, both write back value+1, you've lost one increment. `__sync_fetch_and_add(count, 1)` compiles to a single `lock xadd` instruction — the read-modify-write is indivisible at hardware level.

Use this for any counter in a regular `BPF_MAP_TYPE_HASH`. The alternative is `BPF_MAP_TYPE_PERCPU_HASH` — each CPU gets its own value slot, no atomics needed, but userspace must sum across all CPU copies.

## Struct value initialization with designated initializers

```c
struct conn_stats init = { .packets = 1, .bytes = pkt_len };
```

Named field initialization — unspecified fields are zeroed. Preferred over `= {}` followed by field assignments when you want to set initial values other than zero. If you add fields to `conn_stats` later they are zero-initialized automatically — no accidental garbage from stack. The value struct must also be a stack variable for the same `PTR_TO_STACK` reason as the key.

## Common header file pattern

`conn_key` and `conn_stats` must be defined in both the BPF kernel file and the userspace loader — they are separate compilation units targeting different architectures and cannot share compiled objects. The production pattern is a shared header:

```
connection_tracker/
├── connection_tracker.h      ← struct definitions live here
├── connection_tracker.bpf.c  ← includes the header
└── connection_tracker_loader.c ← includes the header
```

This ensures the structs stay in sync. Divergence between the kernel-side and userspace-side struct definitions causes silent corruption — you're reading map bytes with the wrong field layout.

---