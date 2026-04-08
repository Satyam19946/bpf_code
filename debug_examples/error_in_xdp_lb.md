## Error
```
sudo ./xdp_lb/xdp_lb_loader wlo1
libbpf: prog 'xdp_lb': BPF program load failed: Permission denied
libbpf: prog 'xdp_lb': -- BEGIN PROG LOAD LOG --
0: R1=ctx() R10=fp0
; int xdp_lb(struct xdp_md *ctx) @ xdp_lb.bpf.c:28
0: (b7) r0 = 2                        ; R0_w=2
; void *data_end  = (void *)(long)(ctx->data_end); @ xdp_lb.bpf.c:31
1: (61) r2 = *(u32 *)(r1 +4)          ; R1=ctx() R2_w=pkt_end()
; void *data      = (void *)(long)(ctx->data); @ xdp_lb.bpf.c:30
2: (61) r8 = *(u32 *)(r1 +0)          ; R1=ctx() R8_w=pkt(r=0)
; if ((void *)(eth+1) > data_end){ @ xdp_lb.bpf.c:35
3: (bf) r1 = r8                       ; R1_w=pkt(r=0) R8_w=pkt(r=0)
4: (07) r1 += 14                      ; R1_w=pkt(off=14,r=0)
5: (2d) if r1 > r2 goto pc+123        ; R1_w=pkt(off=14,r=14) R2_w=pkt_end()
; if (bpf_ntohs(eth->h_proto) != ETH_P_IP){ @ xdp_lb.bpf.c:39
6: (71) r3 = *(u8 *)(r8 +13)          ; R3_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff)) R8_w=pkt(r=14)
7: (67) r3 <<= 8                      ; R3_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=0xff00,var_off=(0x0; 0xff00))
8: (71) r4 = *(u8 *)(r8 +12)          ; R4_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff)) R8_w=pkt(r=14)
9: (4f) r3 |= r4                      ; R3_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=0xffff,var_off=(0x0; 0xffff)) R4_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff))
10: (55) if r3 != 0x8 goto pc+118     ; R3_w=8
11: (bf) r3 = r8                      ; R3_w=pkt(r=14) R8_w=pkt(r=14)
12: (07) r3 += 34                     ; R3=pkt(off=34,r=14)
13: (2d) if r3 > r2 goto pc+115       ; R2=pkt_end() R3=pkt(off=34,r=34)
14: (b7) r7 = 0                       ; R7_w=0
; struct service_key key = {}; @ xdp_lb.bpf.c:49
15: (7b) *(u64 *)(r10 -8) = r7        ; R7_w=0 R10=fp0 fp-8_w=0
; __u8 ip_hdr_len = (ip->ihl) * 4; @ xdp_lb.bpf.c:52
16: (71) r3 = *(u8 *)(r8 +14)         ; R3_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff)) R8=pkt(r=34)
17: (67) r3 <<= 2                     ; R3_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=1020,var_off=(0x0; 0x3fc))
18: (57) r3 &= 60                     ; R3_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=60,var_off=(0x0; 0x3c))
; if (ip->protocol == IPPROTO_TCP){ @ xdp_lb.bpf.c:57
19: (71) r2 = *(u8 *)(r8 +23)         ; R2_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff)) R8=pkt(r=34)
20: (15) if r2 == 0x11 goto pc+7      ; R2_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff))
21: (b7) r6 = 0                       ; R6=0
22: (55) if r2 != 0x6 goto pc+10      ; R2=6
; tcp = (void *)ip + ip_hdr_len; @ xdp_lb.bpf.c:58
23: (0f) r1 += r3                     ; R1_w=pkt(id=1,off=14,r=0,smin=smin32=0,smax=umax=smax32=umax32=60,var_off=(0x0; 0x3c)) R3=scalar(smin=smin32=0,smax=umax=smax32=umax32=60,var_off=(0x0; 0x3c))
; dst_port = tcp->dest; @ xdp_lb.bpf.c:59
24: (bf) r3 = r1                      ; R1_w=pkt(id=1,off=14,r=0,smin=smin32=0,smax=umax=smax32=umax32=60,var_off=(0x0; 0x3c)) R3_w=pkt(id=1,off=14,r=0,smin=smin32=0,smax=umax=smax32=umax32=60,var_off=(0x0; 0x3c))
25: (07) r3 += 2                      ; R3_w=pkt(id=1,off=16,r=0,smin=smin32=0,smax=umax=smax32=umax32=60,var_off=(0x0; 0x3c))
26: (bf) r7 = r1                      ; R1_w=pkt(id=1,off=14,r=0,smin=smin32=0,smax=umax=smax32=umax32=60,var_off=(0x0; 0x3c)) R7_w=pkt(id=1,off=14,r=0,smin=smin32=0,smax=umax=smax32=umax32=60,var_off=(0x0; 0x3c))
27: (05) goto pc+4
;  @ xdp_lb.bpf.c:0
32: (69) r4 = *(u16 *)(r3 +0)
invalid access to packet, off=16 size=2, R3(id=1,off=16,r=0)
R3 offset is outside of the packet
processed 29 insns (limit 1000000) max_states_per_insn 0 total_states 2 peak_states 2 mark_read 2
-- END PROG LOAD LOG --
libbpf: prog 'xdp_lb': failed to load: -13
libbpf: failed to load object 'xdp_lb/xdp_lb.bpf.o'
load failed
```

## The structure of a verifier log

Every verifier log has this shape:

```
<instruction number>: <BPF instruction>    ; <register state after this instruction>
```

The verifier simulates your program instruction by instruction, tracking the type and value range of every register after every instruction. When it hits something it can't prove safe, it prints the error and stops.

The error line is always at the bottom, just before the summary:

```
32: (69) r4 = *(u16 *)(r3 +0)
invalid access to packet, off=16 size=2, R3(id=1,off=16,r=0)
R3 offset is outside of the packet
```

This is the instruction that failed. Everything above it is the trail of register state that led here.

---

## Reading the error line itself

```
invalid access to packet, off=16 size=2, R3(id=1,off=16,r=0)
```

Breaking it down:

`off=16` — the verifier computed that r3 points 16 bytes past the start of the packet region it's tracking.

`size=2` — you're trying to read 2 bytes (a `__u16`, the port field).

`r=0` — this is the critical part. `r` is the "verified readable range." `r=0` means the verifier has not proven that any bytes at this pointer are safe to read. The range `[ptr, ptr+0)` is empty — zero bytes proven safe.

`R3 offset is outside of the packet` — because `r=0`, reading even 1 byte from r3 is unproven. Reading 2 bytes (the port) is definitely rejected.

---

## Tracing back how r3 got into this state

Now you read upward from the error to understand how r3 ended up with `r=0`. Follow r3 backward:

```
instruction 25: r3 += 2    R3_w=pkt(id=1,off=16,r=0,...)
instruction 24: r3 = r1    R3_w=pkt(id=1,off=14,r=0,...)
instruction 23: r1 += r3   R1_w=pkt(id=1,off=14,r=0,...)
```

At instruction 23, r1 (which was pointing at the Ethernet header start + 14 = IP header start) has `r3` added to it — that's `ip_hdr_len`. After this, r1 points to the transport header. But look at the `r=0` — the readable range is 0.

The readable range `r=0` means: after computing this pointer by adding a variable offset (`ip_hdr_len`), the verifier has lost the proof that anything at the resulting address is within `data_end`. Adding a variable to a packet pointer resets the proven range to 0 — because the verifier doesn't know how large `ip_hdr_len` is at this point in its simulation, even though you bounded it with `__u8`.

---

## The root cause

You computed the transport header pointer:

```c
tcp = (void *)ip + ip_hdr_len;
```

And then immediately tried to read `tcp->dest` (at offset 2 within tcphdr). But you never did a bounds check on `tcp` after computing it.

This is the pattern from `packet_inspect` applied to a variable-length offset — and it requires a fresh bounds check. Adding `ip_hdr_len` to the IP pointer produces a new pointer whose range the verifier doesn't know. You have to prove it's within `data_end` before reading from it.

---

## The fix

After computing the transport header pointer, add the bounds check before reading any field:

```c
struct tcphdr *tcp = (void *)ip + ip_hdr_len;
if ((void *)(tcp + 1) > data_end)
    return XDP_PASS;

/* NOW the verifier knows tcp through tcp+sizeof(tcphdr) is valid */
dst_port = tcp->dest;
```

The `(tcp + 1) > data_end` check is what advances `r` from 0 to `sizeof(struct tcphdr)` in the verifier's model — exactly what it needs before permitting the read at instruction 32.

---

## One more thing to notice in the log

Look at instruction 10:

```
10: (55) if r3 != 0x8 goto pc+118     ; R3_w=8
```

`0x8` — that's not `ETH_P_IP`. `ETH_P_IP` is `0x0800`. The verifier is showing you that your EtherType comparison is against `0x8` not `0x0800`. This means `bpf_ntohs` expanded in a way that shifted the value — the comparison is actually comparing the right thing at the byte level (clang optimized the ntohs + compare into a byte-swapped constant), but it's worth noticing that the verifier log shows post-optimization constants, not your source-level values.

---

## The systematic approach when you get a verifier error

```
1. find the failing instruction at the bottom
2. read the error message — what type of access failed, what was r=N
3. find which register failed and what type it has (PTR_TO_PACKET with r=0 means no bounds check)
4. trace that register backward through the log to find where it was last given a valid range
5. find the missing bounds check between that point and the failing instruction
6. add the bounds check immediately after the pointer computation that reset r to 0
```