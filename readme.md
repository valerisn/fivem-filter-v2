# fivem-xdp-filter

XDP/eBPF packet filter for FiveM servers. Drops DDoS traffic at the NIC before it ever hits the kernel network stack.

## Requirements

- Linux kernel 5.8+
- `clang` + `llvm`
- `libbpf-dev`
- `iproute2` (for `ip link`)

```
apt install clang llvm libbpf-dev iproute2
```

## Setup

Edit the defines at the top of `filter.c` to match your server:

```c
#define SERVER_IP    0xYOURIPHERE  // your public IP in hex, big-endian
#define SERVER_PORT  30120
```

To convert your IP to hex (e.g. `1.2.3.4`):
```
printf '0x%02X%02X%02X%02X\n' 1 2 3 4
# → 0x01020304
```

## Compile

```bash
clang -O2 -g -target bpf \
  -I/usr/include/$(uname -m)-linux-gnu \
  -c filter.c -o filter.o
```

## Load

```bash
# attach to your network interface (replace eth0 with yours)
ip link set dev eth0 xdp obj filter.o sec xdp

# verify it's attached
ip link show eth0
```

## Unload

```bash
ip link set dev eth0 xdp off
```

## Tuning

All limits are overridable at compile time with `-D`:

| Flag | Default | Description |
|------|---------|-------------|
| `TB_BURST` | 20 | Max burst packets per IP |
| `TB_REFILL_NS` | 5000000 | Token refill interval (ns) — 5ms = 200pps cap |
| `SYN_RATE_NS` | 100000000 | Min gap between SYNs per IP (100ms) |
| `ICMP_RATE_NS` | 1000000000 | Min gap between ICMP per IP (1s) |
| `AMP_LIMIT` | 512 | Bytes — larger UDP from amp ports gets dropped |
| `FLOW_IDLE_NS` | 120000000000 | TCP flow idle timeout (120s) |

Example — tighten the rate limit to 100pps:
```bash
clang -O2 -target bpf -DTB_REFILL_NS=10000000 -c filter.c -o filter.o
```

## Stats

The filter tracks drop reasons in a per-CPU BPF array map called `stats`. Read it with `bpftool`:

```bash
bpftool map dump name stats
```

Indices match the `stat_idx` enum in `filter.c` (`STAT_DROP_BLOCKLIST`, `STAT_DROP_BOGON`, etc.).

## Blocklist / Allowlist

Manage banned or trusted IPs at runtime without reloading:

```bash
# block an IP
bpftool map update name blocklist key hex $(printf '%02x %02x %02x %02x' 1 2 3 4) value hex 01

# allow an IP (bypasses all checks)
bpftool map update name allowlist key hex $(printf '%02x %02x %02x %02x' 5 6 7 8) value hex 01

# unblock
bpftool map delete name blocklist key hex $(printf '%02x %02x %02x %02x' 1 2 3 4)
```
