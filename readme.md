# fivem-xdp-filter

An XDP/eBPF packet filter for FiveM and CFX servers. It runs in the NIC driver,
before `sk_buff` allocation, so dropped traffic costs a few hundred nanoseconds
instead of a full trip through the network stack. On a modern server that is the
difference between absorbing a few million packets per second and falling over.

It is not a substitute for upstream scrubbing. A volumetric attack that fills
your uplink is decided before any packet reaches your kernel. What this handles
is everything that arrives: SYN floods, UDP garbage aimed at the game port,
reflected amplification, spoofed martians, fragment abuse, and the FiveM-specific
`getinfo`/`getstatus` query floods that turn one small packet into a large reply.

## Quick start

```bash
sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev build-essential
make
sudo make install

# Observe first. Nothing is dropped in dry-run mode.
sudo fivemctl load -i eth0 --ip 203.0.113.10 --port 30120 --on dry-run
sudo fivemctl stats --watch 2
```

Leave it in dry-run through a peak evening. If `would have dropped` only ever
covers traffic you are happy to lose, commit:

```bash
sudo fivemctl config --off dry-run
```

Skipping the dry-run step is how people firewall their own player base.

## Requirements

- Linux 5.8 or newer (ringbuf, `bpf_spin_lock`)
- `clang`/`llvm` 10+
- `libbpf` 0.7+ (for `bpf_xdp_attach`), plus `libelf` and `zlib`
- A NIC with native XDP support, otherwise it falls back to generic/skb mode
  automatically. Generic mode still works, just without most of the speed win.

`make check-deps` verifies the toolchain. `make test` runs the unit tests for
the pure-arithmetic parts, needing neither root nor a kernel. `make verify`
loads the program into the kernel and unloads it again, so you can confirm it
passes the verifier without touching a live interface.

## What it does, in order

Every packet takes the same path, and the first rule that matches decides it.

1. **Parse.** Ethernet, up to two VLAN tags (802.1Q and QinQ), then IPv4 or
   IPv6 including a bounded walk of extension headers. Anything non-IP is
   passed straight through. Lengths come from the IP header, not from
   `data_end`, because frames under 60 bytes arrive padded.
2. **Allowlist.** Exact address or IPv4 CIDR. Wins over everything, including
   lockdown mode.
3. **Blocklist.** Same shape. Entries can carry a TTL, expired in-kernel, so
   temporary bans need no daemon to clean up.
4. **Bogons.** Sources that cannot legitimately appear on the public internet:
   RFC1918, CGNAT, loopback, link-local, documentation ranges, multicast,
   reserved. IPv6 gets the equivalent screen on its /64 prefix.
5. **Land attacks.** Source address equal to destination address.
6. **Destination match.** Traffic not aimed at the address you are protecting
   is passed untouched, so this is safe to attach to a shared interface.
7. **Fragments.** Only the first fragment carries L4 headers, so later
   fragments can never be port-matched. That is exactly why attackers send
   them; they are dropped, and the first fragment is rate limited.
8. **Per-protocol handling.** See below.

### UDP

Traffic outside the configured port range is passed. On the game port:

- Oversized packets from known reflection source ports (DNS, NTP, memcached,
  CLDAP, SSDP, Source engine query, and a dozen others) are dropped outright.
  Nothing legitimate ever arrives at a game server from source port 11211.
- Payloads outside `--udp-min`/`--udp-max` are dropped.
- Packets prefixed with `0xFFFFFFFF` are CFX out-of-band queries: `getinfo`,
  `getstatus`, `connect`, `rcon`. These are the cheap-request/expensive-reply
  asymmetry that FiveM query floods abuse, so they get their own per-source
  budget *and* a box-wide ceiling, separate from gameplay traffic. A player
  already in the server never sends them.
- Everything else spends a token from the per-source bucket.

### TCP

- Illegal flag combinations (null, xmas, SYN+FIN, SYN+RST, FIN without ACK,
  URG without ACK) are dropped. No real stack emits them.
- A bare SYN carrying payload is dropped.
- New connections pass three gates: a box-wide SYN ceiling, a per-source SYN
  rate, and a per-source new-connection quota per minute.
- Established traffic is matched against a flow table. In strict mode, a
  non-SYN packet with no matching flow is dropped, which kills the ACK floods
  that would otherwise reach the server's accept queue.

Strict mode has an obvious failure case: connections that existed before the
filter loaded have no flow entry. `--grace` (default 30s) adopts unknown flows
during a learning window at attach time, so loading the filter on a live server
does not disconnect everyone. After the window closes, strict mode applies.

### ICMP

Echo is rate limited per source. Non-echo is *not* dropped by default, because
that category includes path MTU discovery and blackholing it breaks TCP in ways
that are miserable to debug. It is rate limited instead. `--on drop-icmp` if you
really want none of it.

## Rate limiting design

Per-source state lives in a fixed-size hashed array (8 MiB, 131072 slots), not
an LRU hash. Three reasons:

- Memory is bounded and allocated at load. An LRU hash allocates under flood,
  which is when allocation is worst.
- Entries cannot be evicted at the moment they matter. Under a source-rotating
  flood, an LRU evicts precisely the attacker entries you were tracking.
- An array value can carry a `bpf_spin_lock`; an LRU hash value cannot. That
  matters because a token bucket is a read-modify-write, and without a lock it
  races across CPUs on a multi-queue NIC. Every per-source decision for a packet
  happens inside one critical section, so counters are never seen half-updated.

Two sources sharing a slot is resolved by a fingerprint: a mismatch resets the
slot, so colliding sources do not silently rate limit each other. The trade is
that a source-rotating attacker resets slots, which per-source limiting cannot
defend against anyway. That is what the global ceilings are for, since
`--global-syn-pps` and `--global-oob-pps` are the only limits that mean anything
against spoofed sources.

The hash seed is randomised at every load, so nobody can precompute a set of
addresses that all land in one slot.

## fivemctl

```
fivemctl load -i IFACE --ip A.B.C.D [--port 30120] [tunables]
fivemctl unload -i IFACE
fivemctl status
fivemctl stats [--watch [SEC]] [--reset]
fivemctl config [tunables]        show or partially update the live config
fivemctl block   <ip|cidr> [--ttl SEC]
fivemctl unblock <ip|cidr>
fivemctl allow   <ip|cidr> [--ttl SEC]
fivemctl unallow <ip|cidr>
fivemctl list [block|allow]
fivemctl log                      stream sampled drops
```

Every threshold lives in a config map, so `fivemctl config` retunes a running
filter with no recompile and no reattach. Only the options you name are touched.

```bash
fivemctl config --pps 400 --syn-rate 5
fivemctl block 198.51.100.0/24 --ttl 3600
fivemctl log
```

### Tunables

| Option | Default | What it controls |
|---|---|---|
| `--ip` / `--ip6` | none | Address being protected. Without it, every destination on the interface is filtered. |
| `--port` / `--port-hi` | 30120 | Game port, or an inclusive range. |
| `--aux-port` | off | One extra TCP port, typically txAdmin on 40120. |
| `--pps` | 200 | Sustained packets/sec per source. |
| `--burst` | 40 | Per-source burst allowance. |
| `--syn-rate` | 10 | SYN/sec per source. |
| `--icmp-rate` | 1 | ICMP echo/sec per source. |
| `--oob-rate` | 1 | `getinfo`/`getstatus` per sec per source. |
| `--conn-per-min` | 60 | New TCP connections per minute per source. |
| `--global-syn-pps` | 20000 | Box-wide SYN ceiling. 0 disables. |
| `--global-oob-pps` | 2000 | Box-wide OOB query ceiling. 0 disables. |
| `--amp-limit` | 512 | UDP bytes above which known reflection source ports are dropped. |
| `--udp-min` / `--udp-max` | 1 / 1400 | Accepted UDP payload size on the game port. |
| `--flow-idle` | 120 | TCP flow idle timeout, seconds. |
| `--log-sample` | 256 | Emit one event per N drops. |
| `--grace` | 30 | Seconds spent adopting pre-existing TCP flows. |
| `--mode` | auto | `native`, `skb`, or `hw`. |

### Flags

Toggled with `--on NAME` / `--off NAME`.

| Flag | Default | Effect |
|---|---|---|
| `enabled` | on | Master switch. Off means pass everything. |
| `dry-run` | off | Count and log drops, pass the packet anyway. |
| `bogon` | on | Drop unroutable sources. |
| `strict-tcp` | on | Non-SYN TCP requires a known flow. |
| `log` | on | Emit sampled drop events. |
| `drop-icmp` | off | Drop all ICMP rather than rate limiting it. |
| `drop-ipv6` | off | Drop IPv6 outright. |
| `drop-frags` | off | Drop every fragment, including the first. |
| `drop-ip-opts` | off | Drop IPv4 packets carrying options. |
| `drop-oob` | off | Drop all OOB queries. Delists you from server browsers. |
| `lockdown` | off | Drop everything not explicitly allowlisted. Emergency use. |

## Stats

```
$ fivemctl stats --watch 2
counter                                               total   per second
pass                                              182933122      41220.5
per-source token bucket                             9912045       8801.0
global syn ceiling                                  1204551       1980.0
udp amplification source port                        330219        410.5
tcp without established flow                          88210         31.0
bogon / martian source                                12009          4.0
```

Counters are per-CPU and summed on read, so the fast path never contends on
them. Idle counters are hidden.

`fivemctl log` streams a sample of drops with source, destination, ports and
reason, which is the fastest way to work out whether a rule is catching what
you think it is.

## Running under systemd

```bash
sudo make install
sudo cp systemd/fivem-filter.default /etc/default/fivem-filter
sudo editor /etc/default/fivem-filter     # set FF_IFACE, FF_IP, FF_PORT
sudo systemctl enable --now fivem-filter
```

The unit runs with `CAP_BPF` and `CAP_NET_ADMIN` rather than full root.

## Tuning notes

**Start permissive.** The defaults assume a busy server with normal players.
`--pps 200` is generous for gameplay traffic but a client on a bad connection
that retransmits hard can brush against it. Watch `per-source token bucket` in
dry-run before you commit.

**`--conn-per-min 60` is the one people trip over.** A player reconnecting in a
loop, or a server list crawler, can exceed it legitimately. Allowlist known
crawlers rather than raising it for everyone.

**Global ceilings should sit above your real peak, not at it.** They exist to
cap a flood, not to shape normal traffic. Look at `pass` per second at peak and
set the SYN ceiling well above it.

**`--oob-rate 1` will slow how fast you appear in server browsers.** That is
usually the right trade; query traffic is the cheapest attack surface a FiveM
server has. `--on drop-oob` removes you from browsers entirely.

## Limitations

- IPv4 CIDR lists only. IPv6 entries are keyed on the /64 prefix, which is the
  right granularity for rate limiting but means you cannot block a single /128.
- TTLs on exact-match entries expire in-kernel and the entry is deleted on the
  next packet from that source. TTLs on CIDR entries stop matching on time, but
  the row is only reaped when you run `fivemctl list`, because a trie lookup
  gives the kernel no key to delete with.
- No reassembly. Fragmented traffic beyond the first fragment is dropped, not
  buffered.
- XDP is ingress only. Nothing here inspects or shapes outbound traffic.
- Hardware offload mode (`--mode hw`) is accepted but almost certainly will not
  verify on real NICs; the map set is far past what offload engines support.
- The flow table is an LRU of 512K entries. Beyond that, the oldest flows are
  evicted and their next packet is treated as unknown.

## License

GPL-2.0. The BPF program must be GPL to use the kernel's GPL-only helpers.
