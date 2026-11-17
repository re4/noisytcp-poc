# NoisyTCP — C trigger for CVE-2026-99288

A from-scratch C implementation of the trigger described in
[V4bel/NoisyTCP](https://github.com/V4bel/NoisyTCP), the advisory for a
pre-auth Linux kernel TCP race that was fixed by upstream commit
`4e2b3ef19e0e` ("inet: reject unhashed sockets during established lookups").

The advisory ships no exploit code, so this file is built entirely from the
mechanism it documents plus the receive path it names. It drives every
precondition of the bug against a plain TCP listener and fires the race.

Use it only against systems you own or are explicitly authorised to test. A hit
panics the kernel: on a container host that is the whole machine.

---

## 1. The bug in one paragraph

`__inet_lookup_established()` walks the TCP ehash without locks. It matches the
4-tuple, takes a reference, and only then re-checks the tuple — it never checks
whether the object it just pinned is still hashed. Request sockets live in a
`SLAB_TYPESAFE_BY_RCU` cache, so the address of a freed request socket can be
handed to the next allocation while a reader still holds that address. If the
next allocation is a SYN-cookie request for the *same* 4-tuple, the reader sees
the old `sk_hash`, a matching tuple, and a non-zero refcount (the cookie request
is published with refcount 1 by `tcp_get_cookie_sock()`), and returns an object
that is **not in ehash** and has **`rsk_listener == NULL`**. `tcp_v4_rcv()` then
evaluates `sk = req->rsk_listener; ... sk->sk_state` and faults at address
`0x12` (`skc_state` offset) inside the receive softirq.

The window between `inet_match()` and `refcount_inc_not_zero()` is a few
nanoseconds, so the reader has to be preempted exactly there. That is why the
advisory quotes 5 s – 2 min on KVM/QEMU (vCPU preemption) and ~14 hours on a
quiet bare-metal box. This tool maximises the attempt rate and exposes the
timing knobs; it cannot make the target kernel preemptible.

## 2. What the trigger needs

| # | Precondition | How the tool produces it |
|---|---|---|
| 1 | A hashed request socket **R** for tuple **T** | `SYN(T)` while the listener's SYN queue has room → `tcp_conn_request()` → `reqsk_queue_hash_req()` inserts it into ehash |
| 2 | A valid SYN cookie **C** for the same **T** | `SYN(T)` while the SYN queue is full → syncookie path → the SYN-ACK's sequence number is the cookie (valid ≈120 s, and only while a recent queue overflow is recorded) |
| 3 | Free **R** and reallocate its slab slot with the cookie request | `RST(T)` with `seq = rcv_nxt` → `tcp_check_req()` embryonic-reset path → `inet_csk_reqsk_queue_drop()` → `kmem_cache_free()`; then `ACK` carrying **C** → `cookie_v4_check()` → `tcp_get_cookie_sock()` → `inet_reqsk_alloc(..., attach_listener = false)` at the same per-CPU SLUB slot |
| 4 | A concurrent lookup of **T** in another RX context | The lookup packet is sent as two IPv4 fragments. `__skb_flow_dissect()` stops at L3 for fragments, so fragments hash on `{src,dst}` while plain packets hash on the full 4-tuple. With ≥2 RX queues or RPS this lands the lookup on a different CPU than the control packets |

The tool calibrates the target's effective backlog itself (binary search on
"does a further SYN still create a request socket?"), so it needs no knowledge
of `listen(2)`.

## 3. Build

```sh
make            # or: cc -O2 -pthread -o noisytcp noisytcp.c
```

Requirements: Linux, a C11 compiler, and root (`CAP_NET_RAW` for the raw IPv4
and `AF_PACKET` sockets). No external libraries.

## 4. Run

Always start with `probe`, then `verify`, then `race`.

```sh
./noisytcp --victim 192.0.2.10 --port 8080 --mode probe
./noisytcp --victim 192.0.2.10 --port 8080 --mode verify
./noisytcp --victim 192.0.2.10 --port 8080 --mode race --duration 600 --batch 8
```

`probe` sends one SYN and reports the SYN-ACK plus whether the host kernel
leaks RSTs (see §5). `verify` walks all five stages and prints what the target
actually did, including a wire-level check that **R** is really in the ehash.
`race` runs the loop until `--duration` expires or you hit Ctrl-C.

### Modes

| Mode | Purpose |
|---|---|
| `probe` | one SYN/SYN-ACK, host RST-leak check, exit |
| `verify` | calibrate the queue, harvest a cookie, create **R**, prove **R** is hashed, fire one shot |
| `race` | the actual race loop (default) |
| `tw` | alternative setup for targets with `net.ipv4.tcp_syncookies=2`: drive the tuple through TIME_WAIT, then convert the TW socket into a hashed **R** with a SYN whose ISN is past `tw_rcv_nxt`. Requires a listener that accepts and closes immediately |

### Options that matter

| Option | Default | Meaning |
|---|---|---|
| `--batch N` | 8 | tuples raced per round; raise it to amortise the queue refill |
| `--readers N` | 1 | extra fragmented lookups in flight per shot |
| `--fill N` / `--backlog N` | calibrate | skip calibration and use this many queued SYNs |
| `--frag-gap-us` | 20 | delay between the two fragments of the lookup packet |
| `--free-gap-us` | 0 | delay between the completing fragment and the RST that frees **R** |
| `--alloc-gap-us` | 4 | delay between that RST and the cookie ACK that reallocates the slot |
| `--jitter-us` | 4 | random spread added to each gap (phase sweep) |
| `--settle-us` | 300 | delay between packet groups, so the target can process them in order |
| `--spoof` + `--src IP` | off | claim a non-local source address with ARP so the local kernel never sees the SYN-ACKs |
| `--dev NAME` | from route | interface to sniff |
| `--sport-range A-B` | 32768-60999 | source ports used for tuples and filler |
| `--mark N` | 1 | `SO_MARK` on the raw socket, for the RST-suppression rule |
| `--assume-ok` | off | continue even if the host leaks RSTs |
| `--keep-children` | off | do not RST the children the cookie ACK creates |
| `--debug` | off | packet-level tracing |

## 5. The host RST problem (read this before racing)

When the target answers our `SYN(T)` with a SYN-ACK, the **local** kernel sees a
segment for a 4-tuple it has no socket for and replies with a RST whose
`seq = ISN + 1`. That is exactly the in-window reset that drops **R**, and it
arrives before the race even starts. `probe` detects this and the tool refuses
to run.

Two ways to deal with it:

**a) Suppress host RSTs for the source-port range.** The tool marks its own raw
packets with `SO_MARK`, so a rule that exempts marked packets keeps the RSTs it
sends on purpose:

```sh
iptables -I OUTPUT -p tcp --sport 32768:60999 --tcp-flags RST RST \
         -m mark ! --mark 0x1 -j DROP
```

Scope the port range with `--sport-range`. Remove the rule when you are done.

**b) Spoof an address that is not local**, on the same L2 segment as the target:

```sh
./noisytcp --victim 192.0.2.10 --port 8080 --src 192.0.2.99 --spoof --mode race
```

The tool answers ARP for `192.0.2.99`, the SYN-ACKs are delivered to its
`AF_PACKET` socket, and the local IP stack never considers them local, so no RST
is generated. This works only when the target is directly reachable (no
gateway); for routed targets use (a).

## 6. What success looks like

A hit is a kernel panic in the target's receive softirq:

```
BUG: kernel NULL pointer dereference, address: 0000000000000012
RIP: 0010:tcp_v4_rcv+0x44e/0x1280
...
Kernel panic - not syncing: Fatal exception in interrupt
```

On the target you can watch progress with the standard counters:

```sh
nstat -az | grep -E 'SyncookiesSent|SyncookiesRecv|EmbryonicRsts|ListenOverflows'
```

`SyncookiesRecv` ≈ one per cookie ACK and `EmbryonicRsts` ≈ one per in-window
RST mean stages 2 and 3 are working.

Without a hit, the run is still informative: `cookies` should track attempts,
and with `--debug` every probe shows whether the queue was full (`flags=0x12`,
SYN-ACK) or a request socket existed (`flags=0x10`, challenge ACK).

## 7. Tuning

The race is a phase-alignment problem between two CPUs, so the gaps matter
more than raw packet rate.

* `--batch 8..32` amortises the queue refill; try larger batches on servers
  with a large `listen()` backlog.
* `--free-gap-us` / `--alloc-gap-us` set the distance between the completing
  fragment, the RST and the cookie ACK. Smaller is tighter; if the ACK keeps
  finding **R** still present, the RST is arriving too late — reduce or
  randomise.
* `--jitter-us` sweeps the phase. A run with jitter 0 and a run with jitter
  ~10 µs are different experiments; try both.
* `--readers 2..4` keeps several lookups in flight around the free/realloc.
* SSDs and idle CPUs help the attacker's send path; the target's preemption
  behaviour dominates.

The target must have two or more RX queues, or RPS enabled, for the fragment
trick to split the lookup from the control packets. A target with a single queue
and RPS disabled cannot be triggered this way at all (that is also mitigation #2
in the advisory).

## 8. Limitations

* This is a DoS, not RCE. The advisory describes the NULL-dereference panic as
  the practical outcome; the "full child socket ABA" path is acknowledged as
  hard to trigger and is not implemented here.
* Whether the race closes depends on the target kernel being preempted inside a
  nanosecond-scale window. On a quiet bare-metal target expect hours; on a
  preemptible VM minutes. The tool cannot create that preemption.
* `tw` mode only works against a listener that accepts and closes immediately
  (a benchmark listener, not nginx).
* The calibration and the `verify` checks assume ICMP is not filtered in a way
  that breaks the SYN/SYN-ACK exchange.

## 9. Layout

```
noisytcp.c   the whole trigger: packet I/O, sniffing, ARP, calibration, modes
Makefile     build
README.md    this file
```

## 10. References

* Advisory: <https://github.com/V4bel/NoisyTCP>
* Fix: `4e2b3ef19e0e` — "inet: reject unhashed sockets during established
  lookups", <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4e2b3ef19e0e>
* Relevant paths: `net/ipv4/inet_hashtables.c` (`__inet_lookup_established`),
  `net/ipv4/tcp_ipv4.c` (`tcp_v4_rcv`), `net/ipv4/syncookies.c`
  (`cookie_v4_check`, `tcp_get_cookie_sock`), `net/ipv4/tcp_minisocks.c`
  (`tcp_check_req`), `net/ipv4/tcp_input.c` (`tcp_conn_request`),
  `net/core/flow_dissector.c` (fragment hashing).
