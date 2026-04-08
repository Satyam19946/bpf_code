## Lines unique to `packet_counter.bpf.c`

---

### The map declaration

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key,   __u8);
    __type(value, __u64);
} proto_count SEC(".maps");
```

We covered what the macros expand to. Now let's talk about what `BPF_MAP_TYPE_HASH` actually means in terms of kernel behavior — because the map type you choose has real consequences for your program.

`BPF_MAP_TYPE_HASH` is defined in `linux/bpf.h` as enum value 1. When libbpf calls `bpf(BPF_MAP_CREATE, ...)` with this type, the kernel allocates a hash table using its internal `htab_map_ops` vtable — the same vtable dispatch model you learned in Phase 3. The kernel pre-allocates the bucket array and a pool of element nodes for up to `max_entries` entries at map creation time. This is why you set `max_entries` at declaration — the memory is committed upfront, not lazily.

For `BPF_MAP_TYPE_HASH` specifically, the kernel uses a variant of a chained hash table internally. Each bucket is a head of a linked list of elements. Lookup walks the chain comparing keys. For small key sizes like our `__u8` (one byte), the hash is trivially fast and collisions are minimal with 256 buckets for 256 possible keys.

The full `bpf(BPF_MAP_CREATE, ...)` call libbpf makes for our map, expanded:

```c
union bpf_attr attr = {
    .map_type    = BPF_MAP_TYPE_HASH,   // which map implementation
    .key_size    = 1,                    // sizeof(__u8)
    .value_size  = 8,                    // sizeof(__u64)
    .max_entries = 256,                  // pre-allocated capacity
    .map_flags   = 0,                    // no special flags
    .map_name    = "proto_count",        // from the variable name
};
int map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
```

`map_fd` is a file descriptor in the loader process's fd table. This is the same fd your loader uses when it calls `bpf_map_lookup_elem(map_fd, &key, &value)` from userspace. Maps are kernel objects referenced by fd — the same model as files, sockets, and epoll instances. The map exists independently of any BPF program — you could create a map without ever loading a program, or load a program and never attach it.

One important consequence: when all file descriptors referencing a map are closed and no loaded BPF program holds a reference to it, the kernel frees the map. If your loader exits without pinning the map to `/sys/fs/bpf/`, the map and all its data disappear with it. Pinning is how you persist maps across loader restarts — relevant for Phase 5 where your CNI daemon will restart and needs to recover map state.

---

### Extracting the protocol

```c
__u8 proto = ip->protocol;
```

`ip->protocol` is defined in `linux/ip.h` as a `__u8` field at byte offset 9 of `struct iphdr`. It holds the IANA protocol number of the next layer — 1 for ICMP, 6 for TCP, 17 for UDP. No byte-swapping needed because it's a single byte — endianness only matters for multi-byte fields.

We copy it into a local stack variable `proto` rather than using `&ip->protocol` directly as the map key. This matters: `bpf_map_lookup_elem` and `bpf_map_update_elem` take a pointer to the key. If you passed `&ip->protocol` directly, you'd be passing a pointer into the packet buffer — a `PTR_TO_PACKET`. The verifier rejects this. Map key and value pointers must come from the stack (`PTR_TO_STACK`) or map values (`PTR_TO_MAP_VALUE`). Copying to a local variable puts it on the BPF stack, making it a valid key pointer.

This is a rule worth internalizing: **helpers that take key/value pointers require stack or map pointers, never packet pointers.**

---

### The lookup

```c
__u64 *count = bpf_map_lookup_elem(&proto_count, &proto);
```

`bpf_map_lookup_elem` is helper number 1 — `BPF_FUNC_map_lookup_elem` in `linux/bpf.h`. It takes a pointer to the map and a pointer to the key, and returns either a pointer directly into the map's value slot or NULL.

The return type being a direct pointer into map memory (not a copy) is fundamental. It means:

- Writing through `count` modifies the map value in place
- The pointer is valid only within this BPF program invocation — you cannot store it in a map or pass it across tail calls
- The verifier tracks it as `PTR_TO_MAP_VALUE_OR_NULL` until you check it, then as `PTR_TO_MAP_VALUE` after

The verifier's treatment of this return value is stricter than a normal nullable pointer in C. In regular C, a compiler might warn about a NULL dereference but won't stop compilation. The BPF verifier will reject the program outright if any code path dereferences `count` without a prior NULL check — even if you know logically that the key always exists. Static proof is required, not runtime behavior.

---

### The atomic increment

```c
__sync_fetch_and_add(count, 1);
```

This is a GCC atomic built-in that compiles to a single atomic add instruction — `lock xadd` on x86. The `lock` prefix makes the read-modify-write indivisible across CPU cores.

Why this matters specifically for XDP: your program runs in softirq context during NAPI poll. On a multi-core machine, multiple cores can be in NAPI poll simultaneously, each processing a different packet, each running your XDP program. Without atomics, two cores reading the same map value, incrementing locally, and writing back would produce a lost update — a classic read-modify-write race.

The alternative to atomic operations is `BPF_MAP_TYPE_PERCPU_HASH`. With per-CPU maps, each CPU core has its own independent copy of every value. No locking needed because cores never share a value slot. The tradeoff: your userspace reader must sum across all CPU copies to get the total count. For a counter program either works — `PERCPU_HASH` is faster at high packet rates, regular `HASH` with atomics is simpler to read from userspace.

For Phase 5's service map (ClusterIP → backends), you'll use regular `HASH` without atomics — map updates happen from the control plane daemon (single writer), not from the packet processing path (multiple concurrent readers are fine without atomics because they don't modify).

---

### The conditional insert

```c
} else {
    __u64 init = 1;
    bpf_map_update_elem(&proto_count, &proto, &init, BPF_NOEXIST);
}
```

`bpf_map_update_elem` is helper number 2 — `BPF_FUNC_map_update_elem`. It inserts or updates a key-value pair. The fourth argument is a flag from `linux/bpf.h`:

```c
#define BPF_ANY     0   // create or update
#define BPF_NOEXIST 1   // create only — fail if key exists
#define BPF_EXIST   2   // update only — fail if key doesn't exist
```

`BPF_NOEXIST` here is not just defensive programming — it's correct concurrent behavior. Between the `bpf_map_lookup_elem` returning NULL and this `bpf_map_update_elem` executing, another CPU core could have processed a packet with the same protocol and inserted the key. If we used `BPF_ANY`, we'd overwrite that core's insert with 1, losing its count. With `BPF_NOEXIST`, our insert fails silently and the other core's entry (with value 1) stands. Either way the map ends up with exactly one entry for this protocol — the count might be off by one in a race, but the entry exists and subsequent increments via `__sync_fetch_and_add` will be correct.

`init` must be a stack variable because `bpf_map_update_elem` requires `PTR_TO_STACK` for the value pointer — same rule as the key pointer above. You cannot write `bpf_map_update_elem(&proto_count, &proto, &((__u64){1}), BPF_NOEXIST)` in BPF C the way you might in userspace C.

The return value of `bpf_map_update_elem` is an int — 0 on success, negative errno on failure. We ignore it here. In production BPF code you'd typically track insert failures via a separate counter map, since `bpf_printk` on every failed insert would flood trace_pipe.

---

Two patterns not in this program that will appear constantly in CNIs:

**Nested lookups** — looking up a value in one map, using that value as a key in a second map. The verifier requires a NULL check after each lookup before the result can be used as the next key. This is the pattern for your service map: lookup `{dst_ip, port}` → get backend list index → lookup backend list → get `{backend_ip, backend_port}`.

**Map-in-map** — `BPF_MAP_TYPE_ARRAY_OF_MAPS` or `BPF_MAP_TYPE_HASH_OF_MAPS`. An outer map whose values are file descriptors of inner maps. Used in Cilium's policy map — outer key is security identity, inner map contains the allowed destination ports. You won't need this immediately but it's worth knowing it exists.