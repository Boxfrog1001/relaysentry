"""Adaptive defense engine for RelaySentry.

Provides:
- 3-state attack hysteresis controller (prevents mitigation oscillation on pulsing floods)
- Fixed-capacity telemetry ring buffer for bounded-RAM watch sessions
- Anonymized Shannon peer-distribution entropy & flood-shape classification
- Strict non-relay kernel nftables (netdev ingress + raw notrack) rule planning
- Tor torrc / Equi-X PoW defense recommendations based on live bottleneck signals
- Compilable dual-stack eBPF/XDP C shield template with consensus allowlist + SYN token bucket
"""

import ipaddress
import math
import shutil
import subprocess
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

SEVERITY_RANK = {
    "NORMAL": 0,
    "ELEVATED_PRESSURE": 1,
    "ACTIVE_DOS_PRESSURE": 2,
}


def compute_shannon_entropy(counts: Iterable[int]) -> float:
    """Compute Shannon entropy (bits) of per-peer socket distribution."""
    positive = [c for c in counts if c > 0]
    total = sum(positive)
    if total <= 0 or len(positive) <= 1:
        return 0.0
    entropy = 0.0
    for c in positive:
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


def classify_flood_shape(counts: Iterable[int], total_sockets: int) -> tuple[str, float]:
    """Classify non-relay flood distribution using anonymized bucket entropy."""
    vals = [c for c in counts if c > 0]
    if total_sockets <= 0 or not vals:
        return "IDLE", 0.0
    entropy = compute_shannon_entropy(vals)
    top_share = max(vals) / total_sockets
    if top_share >= 0.45 or (entropy < 2.0 and total_sockets >= 25):
        return "CONCENTRATED_SOURCE", entropy
    if entropy >= 4.0 and total_sockets >= 50:
        return "DISTRIBUTED_BOTNET", entropy
    return "MIXED_TRAFFIC", entropy


class DefenseStateMachine:
    """Three-state DoS escalation controller with hold-time hysteresis."""

    def __init__(self, hold_seconds: float = 60.0):
        if hold_seconds < 0:
            raise ValueError("hold_seconds must be >= 0")
        self._hold_seconds = float(hold_seconds)
        self._effective_severity = "NORMAL"
        self._last_peak_ts: float | None = None

    @property
    def effective_severity(self) -> str:
        return self._effective_severity

    def step(self, raw_severity: str, now_monotonic: float | None = None) -> tuple[str, float]:
        """Update hysteresis state; jump up immediately, hold before stepping down."""
        now = time.monotonic() if now_monotonic is None else float(now_monotonic)
        raw_rank = SEVERITY_RANK.get(raw_severity, 0)
        eff_rank = SEVERITY_RANK.get(self._effective_severity, 0)

        if raw_rank >= eff_rank:
            self._effective_severity = raw_severity
            if raw_rank > 0:
                self._last_peak_ts = now
            return self._effective_severity, 0.0

        if self._last_peak_ts is None:
            self._effective_severity = raw_severity
            return self._effective_severity, 0.0

        elapsed = now - self._last_peak_ts
        if elapsed >= self._hold_seconds:
            self._effective_severity = raw_severity
            self._last_peak_ts = now if raw_rank > 0 else None
            return self._effective_severity, 0.0

        remaining = max(0.0, self._hold_seconds - elapsed)
        return self._effective_severity, remaining


@dataclass(frozen=True)
class ShieldWindowSample:
    """Compact bounded-memory record of a single monitoring tick."""

    timestamp_monotonic: float
    raw_severity: str
    effective_severity: str
    total_sockets: int
    syn_recv: int
    queue_bytes: int
    nonrelay_entropy_bits: float
    sample_stride: int


class TelemetryRingBuffer:
    """Fixed-capacity ring buffer preventing unbounded RAM growth in --watch runs."""

    def __init__(self, maxlen: int = 64):
        if maxlen < 1:
            raise ValueError("maxlen must be >= 1")
        self._buf: deque[ShieldWindowSample] = deque(maxlen=maxlen)

    def push(self, sample: ShieldWindowSample) -> None:
        self._buf.append(sample)

    def snapshot(self) -> tuple[ShieldWindowSample, ...]:
        return tuple(self._buf)

    def peak_sockets(self) -> int:
        return max((s.total_sockets for s in self._buf), default=0)


def generate_kernel_nft_rules(
    disclosed_flooders: list[tuple[str, tuple[int, ...]]],
    ttl_seconds: int = 120,
    rate_limit: str = "10/second",
    burst: int = 20,
) -> list[str]:
    """Emit pre-conntrack raw notrack + input rate-limit nft rules for verified non-relay flooders."""
    hints: list[str] = []
    for raw_ip, ports in disclosed_flooders:
        addr = ipaddress.ip_address(raw_ip)
        valid_ports = [p for p in sorted(set(ports)) if 1 <= p <= 65535]
        if not valid_ports:
            continue
        proto = "ip6 saddr" if addr.version == 6 else "ip saddr"
        port_expr = ", ".join(str(p) for p in valid_ports)
        # Self-contained per-IP rate-limit hint (does not require pre-existing inet raw/filter tables).
        hints.append(
            f"nft add table inet relaysentry_hints && "
            f"nft 'add chain inet relaysentry_hints input {{ type filter hook input priority filter; policy accept; }}' && "
            f"nft 'add rule inet relaysentry_hints input {proto} {addr.compressed} "
            f"tcp dport {{ {port_expr} }} ct state new limit rate over {rate_limit} burst {burst} packets drop'  # review TTL={ttl_seconds}s"
        )
    return hints


def generate_tor_defense_hints(
    reasons: Iterable[str],
    flood_shape: str,
    effective_severity: str,
) -> list[str]:
    """Produce actionable Tor torrc / sysctl hardening guidance from telemetry signals."""
    reason_text = " ".join(reasons)
    hints: list[str] = []

    if effective_severity == "NORMAL":
        return hints

    if "THUNDERSTORM_BEGIN_DIR_FLOOD" in reason_text or "HALF_OPEN_BEGIN_DIR_BYPASS_SUSPECTED" in reason_text:
        hints.append(
            "BEGIN_DIR Thunderstorm shield (Tor >= 0.4.9.15): ensure DoSBeginDirRateEnabled 1 ; "
            "DoSBeginDirLimitEnabled 1 ; NumCPUs 16 ; MaxMemInQueues 2 GB (emergency HSDir circuit breaker: DirCache 0)"
        )

    if "HALF_OPEN_BEGIN_DIR_BYPASS_SUSPECTED" in reason_text or "METRICS_PORT_UNRESPONSIVE" in reason_text:
        hints.append(
            "Event-loop / half-open BEGIN_DIR stall detected: kernel socket queues are filling before "
            "HTTP GET completion; isolate non-relay flooders early via XDP/nftables and monitor procfs directly."
        )

    if "ONIONSKIN_DROPS" in reason_text or "TOR_OOM_TRIGGERED" in reason_text:
        hints.append(
            "torrc CPU/OOM shield: DoSCircuitCreationEnabled 1 ; DoSCircuitCreationMinConnections 3 ; "
            "DoSCircuitCreationRate 3 ; DoSCircuitCreationBurst 90 ; NumCPUs 16 (enable HiddenServicePoWDefensesEnabled 1 if .onion)"
        )

    if "KERNEL_SOCKET_QUEUE_BACKPRESSURE" in reason_text or "NONRELAY_PEER_FLOOD" in reason_text:
        hints.append(
            "Kernel sk_buff page-bloat cure (VPS/virtio_net): sysctl -w net.core.high_order_alloc_disable=1 "
            "(prevents small stalled queued packets pinning 32 KiB slab pages invisible to MaxMemInQueues)"
        )

    if "HIGH_SYN_RECV_BACKLOG" in reason_text or "NONRELAY_PEER_FLOOD" in reason_text or flood_shape == "DISTRIBUTED_BOTNET":
        hints.append(
            "Kernel + torrc connection shield: sysctl -w net.ipv4.tcp_syncookies=1 ; "
            "DoSConnectionEnabled 1 ; DoSConnectionMaxConcurrentCount 50 ; DoSRefuseSingleHopClientRendezvous 1"
        )

    if "CONCENTRATED_RELAY_CLUSTER" in reason_text or "HEAVY_CONSENSUS_RELAY_PEERS" in reason_text:
        hints.append(
            "Consensus relay boundary: DO NOT globally firewall consensus relay IPs (risks partitioning mesh reachability); "
            "rely on DoSBeginDirLimitEnabled 1, DoSCircuitCreationEnabled 1, and ORCONN cross-checks."
        )

    if flood_shape == "CONCENTRATED_SOURCE":
        hints.append(
            "Concentrated flood detected (low peer entropy): --reveal-flooders + --emit-nft-hints or XDP blocked map "
            "can isolate top non-relay flooders while leaving honest Tor users untouched."
        )
    elif flood_shape == "DISTRIBUTED_BOTNET":
        hints.append(
            "Distributed flood detected (high peer entropy): per-IP bans alone are insufficient; "
            "deploy --emit-xdp-c per-IP SYN token bucket + tcp_syncookies + Tor Equi-X PoW."
        )

    return hints


def generate_nft_consensus_sync(
    consensus_ips: Iterable[str],
    ports: set[int],
    conn_limit: int = 25,
    rate_limit: str = "10/second",
    burst: int = 20,
    ban_timeout: str = "30m",
    allow_cidrs: Iterable[str] = (),
) -> str:
    """Emit atomic, idempotent nftables consensus & --allow-cidr allowlist + per-IP DoS shield."""
    sorted_ports = [p for p in sorted(ports) if 1 <= p <= 65535]
    if not sorted_ports:
        raise ValueError("At least one valid TCP port (1..65535) is required")
    port_expr = ", ".join(str(p) for p in sorted_ports)

    v4_ips: list[str] = []
    v6_ips: list[str] = []
    for raw_ip in consensus_ips:
        try:
            addr = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if addr.version == 4:
            v4_ips.append(addr.compressed)
        else:
            v6_ips.append(addr.compressed)

    allow_v4: list[str] = ["127.0.0.0/8"]
    allow_v6: list[str] = ["::1/128"]
    for raw_cidr in allow_cidrs:
        if not raw_cidr or not str(raw_cidr).strip():
            continue
        try:
            net = ipaddress.ip_network(str(raw_cidr).strip(), strict=False)
        except ValueError:
            continue
        if net.version == 4:
            allow_v4.append(net.compressed)
        else:
            allow_v6.append(net.compressed)

    v4_sorted = sorted(set(v4_ips))
    v6_sorted = sorted(set(v6_ips))
    allow_v4_sorted = sorted(set(allow_v4))
    allow_v6_sorted = sorted(set(allow_v6))
    lines = [
        "#!/usr/sbin/nft -f",
        "# RelaySentry Consensus-Safe ORPort Shield (preserves all known Tor relays & --allow-cidr)",
        f"# Apply atomically: ./bin/relaysentry --port {sorted_ports[0]} --emit-nft-consensus | sudo nft -f -",
        "add table inet relaysentry_shield",
        "delete table inet relaysentry_shield",
        "table inet relaysentry_shield {",
        "    set allow_net4 {",
        "        type ipv4_addr",
        "        flags interval",
        "    }",
        "    set allow_net6 {",
        "        type ipv6_addr",
        "        flags interval",
        "    }",
        "    set known_relays4 {",
        "        type ipv4_addr",
        "    }",
        "    set known_relays6 {",
        "        type ipv6_addr",
        "    }",
        "    set tor_ddos4 {",
        "        type ipv4_addr",
        "        size 65536",
        "        flags dynamic, timeout",
        f"        timeout {ban_timeout}",
        "    }",
        "    set tor_ddos6 {",
        "        type ipv6_addr",
        "        size 65536",
        "        flags dynamic, timeout",
        f"        timeout {ban_timeout}",
        "    }",
        "    set tor_syn4 {",
        "        type ipv4_addr",
        "        size 65536",
        "        flags dynamic, timeout",
        "        timeout 60s",
        "    }",
        "    set tor_syn6 {",
        "        type ipv6_addr",
        "        size 65536",
        "        flags dynamic, timeout",
        "        timeout 60s",
        "    }",
        "    set connlimit4 {",
        "        type ipv4_addr",
        "        size 65536",
        "        flags dynamic, timeout",
        "        timeout 120s",
        "    }",
        "    set connlimit6 {",
        "        type ipv6_addr",
        "        size 65536",
        "        flags dynamic, timeout",
        "        timeout 120s",
        "    }",
        "    chain input {",
        "        type filter hook input priority filter; policy accept;",
        "    }",
        "}",
        "flush chain inet relaysentry_shield input",
        f"add rule inet relaysentry_shield input tcp dport {{ {port_expr} }} ip saddr @allow_net4 accept",
        f"add rule inet relaysentry_shield input tcp dport {{ {port_expr} }} ip6 saddr @allow_net6 accept",
        f"add rule inet relaysentry_shield input tcp dport {{ {port_expr} }} ip saddr @known_relays4 accept",
        f"add rule inet relaysentry_shield input tcp dport {{ {port_expr} }} ip6 saddr @known_relays6 accept",
        f"add rule inet relaysentry_shield input tcp dport {{ {port_expr} }} ip saddr @tor_ddos4 drop",
        f"add rule inet relaysentry_shield input tcp dport {{ {port_expr} }} ip6 saddr @tor_ddos6 drop",
        f"add rule inet relaysentry_shield input tcp dport {{ {port_expr} }} ct state new ip saddr != @known_relays4 add @tor_syn4 {{ ip saddr limit rate over {rate_limit} burst {burst} packets }} add @tor_ddos4 {{ ip saddr }} drop",
        f"add rule inet relaysentry_shield input tcp dport {{ {port_expr} }} ct state new ip6 saddr != @known_relays6 add @tor_syn6 {{ ip6 saddr limit rate over {rate_limit} burst {burst} packets }} add @tor_ddos6 {{ ip6 saddr }} drop",
        f"add rule inet relaysentry_shield input tcp dport {{ {port_expr} }} ct state new ip saddr != @known_relays4 add @connlimit4 {{ ip saddr ct count over {conn_limit} }} drop",
        f"add rule inet relaysentry_shield input tcp dport {{ {port_expr} }} ct state new ip6 saddr != @known_relays6 add @connlimit6 {{ ip6 saddr ct count over {conn_limit} }} drop",
        "flush set inet relaysentry_shield allow_net4",
        "flush set inet relaysentry_shield allow_net6",
        "flush set inet relaysentry_shield known_relays4",
        "flush set inet relaysentry_shield known_relays6",
    ]
    chunk_size = 256
    for idx in range(0, len(allow_v4_sorted), chunk_size):
        chunk = ", ".join(allow_v4_sorted[idx : idx + chunk_size])
        lines.append(f"add element inet relaysentry_shield allow_net4 {{ {chunk} }}")
    for idx in range(0, len(allow_v6_sorted), chunk_size):
        chunk = ", ".join(allow_v6_sorted[idx : idx + chunk_size])
        lines.append(f"add element inet relaysentry_shield allow_net6 {{ {chunk} }}")
    for idx in range(0, len(v4_sorted), chunk_size):
        chunk = ", ".join(v4_sorted[idx : idx + chunk_size])
        lines.append(f"add element inet relaysentry_shield known_relays4 {{ {chunk} }}")
    for idx in range(0, len(v6_sorted), chunk_size):
        chunk = ", ".join(v6_sorted[idx : idx + chunk_size])
        lines.append(f"add element inet relaysentry_shield known_relays6 {{ {chunk} }}")
    return "\n".join(lines)


def _validate_pin_dir(pin_dir: str) -> str:
    """Validate BPF bpffs pin directory path cleanly against traversal/injection."""
    if not pin_dir or not pin_dir.startswith("/") or any(c.isspace() or c in ";|&$`\0" for c in pin_dir):
        raise ValueError(f"Invalid bpffs pin directory: {pin_dir!r}")
    return pin_dir.rstrip("/") or "/"


def _format_hex_bytes(raw: bytes) -> str:
    """Format raw address bytes as space-separated hex pairs for bpftool."""
    return " ".join(f"{b:02x}" for b in raw)


def generate_xdp_map_sync(
    consensus_ips: Iterable[str],
    blocked_ips: Iterable[str] = (),
    pin_dir: str = "/sys/fs/bpf/relaysentry",
    unblock_ips: Iterable[str] = (),
) -> str:
    """Emit a bpftool batch script syncing allow_relay_v4/6 and blocked_v4/6 maps."""
    safe_dir = _validate_pin_dir(pin_dir)
    lines = [
        f"# RelaySentry XDP/eBPF map sync batch (bpffs={safe_dir})",
        f"# Apply atomically: ./bin/relaysentry --port 9001 --emit-xdp-sync | sudo bpftool batch file -",
    ]

    v4_allow: list[ipaddress.IPv4Address] = []
    v6_allow: list[ipaddress.IPv6Address] = []
    allow_set: set[str] = set()
    for raw_ip in consensus_ips:
        try:
            addr = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        allow_set.add(addr.compressed)
        if addr.version == 4:
            v4_allow.append(addr)
        else:
            v6_allow.append(addr)

    for addr4 in sorted(set(v4_allow), key=lambda a: int(a)):
        lines.append(
            f"map update pinned {safe_dir}/allow_relay_v4 key hex {_format_hex_bytes(addr4.packed)} value hex 01 any"
        )
    for addr6 in sorted(set(v6_allow), key=lambda a: int(a)):
        lines.append(
            f"map update pinned {safe_dir}/allow_relay_v6 key hex {_format_hex_bytes(addr6.packed)} value hex 01 any"
        )

    zero_u64 = "00 00 00 00 00 00 00 00"
    for raw_ip in sorted(set(blocked_ips)):
        try:
            addr = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if addr.compressed in allow_set:
            continue
        mname = "blocked_v4" if addr.version == 4 else "blocked_v6"
        lines.append(
            f"map update pinned {safe_dir}/{mname} key hex {_format_hex_bytes(addr.packed)} value hex {zero_u64} any"
        )

    for raw_ip in sorted(set(unblock_ips)):
        try:
            addr = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        mname = "blocked_v4" if addr.version == 4 else "blocked_v6"
        lines.append(
            f"map delete pinned {safe_dir}/{mname} key hex {_format_hex_bytes(addr.packed)}"
        )

    return "\n".join(lines)


def render_xdp_shield_c(
    ports: set[int],
    syn_rate_per_sec: int = 12,
    syn_burst: int = 24,
) -> str:
    """Render dual-stack Linux XDP/eBPF ingress C filter with consensus allowlist & SYN token bucket."""
    sorted_ports = [p for p in sorted(ports) if 1 <= p <= 65535]
    if not sorted_ports:
        raise ValueError("At least one valid TCP port (1..65535) is required")
    port_checks = " || ".join(f"dport == {p}" for p in sorted_ports)
    refill_ns = max(1_000_000, 1_000_000_000 // max(1, syn_rate_per_sec))

    return f"""// RelaySentry v0.3 Dual-Stack XDP/eBPF Shield (O(1) NIC-ring SYN token bucket)
// Compile : clang -O2 -g -target bpf -c relaysentry_xdp.c -o relaysentry_xdp.o
// Pin+Load: sudo bpftool prog load relaysentry_xdp.o /sys/fs/bpf/relaysentry_xdp_prog pinmaps /sys/fs/bpf/relaysentry
// Attach  : sudo bpftool net attach xdp pinned /sys/fs/bpf/relaysentry_xdp_prog dev <IFACE>
// SyncMap : ./bin/relaysentry --port {sorted_ports[0]} --emit-xdp-sync | sudo bpftool batch file -
// Enforce : sudo ./bin/relaysentry --port {sorted_ports[0]} --enforce-shield --shield-backend xdp --watch 5

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define SYN_BURST        {syn_burst}U
#define TOKEN_REFILL_NS  {refill_ns}ULL

struct vlan_hdr_min {{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
}};

struct bucket_state {{
    __u64 last_ns;
    __u32 tokens;
}};

struct ipv6_key {{
    __u8 addr[16];
}};

struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __be32);
    __type(value, __u8);
}} allow_relay_v4 SEC(".maps");

struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct ipv6_key);
    __type(value, __u8);
}} allow_relay_v6 SEC(".maps");

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __be32);
    __type(value, __u64);
}} blocked_v4 SEC(".maps");

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ipv6_key);
    __type(value, __u64);
}} blocked_v6 SEC(".maps");

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __be32);
    __type(value, struct bucket_state);
}} syn_bucket_v4 SEC(".maps");

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct ipv6_key);
    __type(value, struct bucket_state);
}} syn_bucket_v6 SEC(".maps");

static __always_inline int is_monitored_port(__u16 dport) {{
    return ({port_checks});
}}

static __always_inline int consume_token(struct bucket_state *st, __u64 now_ns) {{
    __u64 elapsed = now_ns > st->last_ns ? (now_ns - st->last_ns) : 0ULL;
    __u64 added = elapsed / TOKEN_REFILL_NS;
    if (added > 0) {{
        __u32 new_tokens = st->tokens + (__u32)(added > SYN_BURST ? SYN_BURST : added);
        st->tokens = new_tokens > SYN_BURST ? SYN_BURST : new_tokens;
        st->last_ns = now_ns;
    }}
    if (st->tokens == 0)
        return 0;
    st->tokens -= 1;
    return 1;
}}

SEC("xdp")
int relaysentry_xdp_shield(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __be16 proto = eth->h_proto;
    void *l3 = (void *)(eth + 1);
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {{
        struct vlan_hdr_min *vh = l3;
        if ((void *)(vh + 1) > data_end)
            return XDP_PASS;
        proto = vh->h_vlan_encapsulated_proto;
        l3 = (void *)(vh + 1);
    }}

    if (proto == bpf_htons(ETH_P_IP)) {{
        struct iphdr *iph = l3;
        if ((void *)(iph + 1) > data_end || iph->ihl < 5 || iph->protocol != IPPROTO_TCP)
            return XDP_PASS;
        struct tcphdr *tcph = (struct tcphdr *)((unsigned char *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;

        __u16 dport = bpf_ntohs(tcph->dest);
        if (!is_monitored_port(dport))
            return XDP_PASS;

        __be32 src = iph->saddr;
        if (bpf_map_lookup_elem(&allow_relay_v4, &src))
            return XDP_PASS;

        __u64 *drops = bpf_map_lookup_elem(&blocked_v4, &src);
        if (drops) {{
            __sync_fetch_and_add(drops, 1);
            return XDP_DROP;
        }}

        if (tcph->syn && !tcph->ack) {{
            __u64 now = bpf_ktime_get_ns();
            struct bucket_state *st = bpf_map_lookup_elem(&syn_bucket_v4, &src);
            if (!st) {{
                struct bucket_state init = {{ .last_ns = now, .tokens = SYN_BURST - 1 }};
                bpf_map_update_elem(&syn_bucket_v4, &src, &init, BPF_ANY);
                return XDP_PASS;
            }}
            if (!consume_token(st, now))
                return XDP_DROP;
        }}
        return XDP_PASS;
    }}

    if (proto == bpf_htons(ETH_P_IPV6)) {{
        struct ipv6hdr *ip6h = l3;
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;
        __u8 nexthdr = ip6h->nexthdr;
        void *l4 = (void *)(ip6h + 1);
        #pragma unroll
        for (int i = 0; i < 4; i++) {{
            if (nexthdr == IPPROTO_TCP)
                break;
            if (nexthdr == 0 || nexthdr == 43 || nexthdr == 60) {{
                struct ipv6_opt_hdr *opt = l4;
                if ((void *)(opt + 1) > data_end)
                    return XDP_PASS;
                nexthdr = opt->nexthdr;
                l4 = (void *)((unsigned char *)opt + ((opt->hdrlen + 1) * 8));
            }} else if (nexthdr == 44) {{
                struct frag_hdr *frag = l4;
                if ((void *)(frag + 1) > data_end)
                    return XDP_PASS;
                nexthdr = frag->nexthdr;
                l4 = (void *)(frag + 1);
            }} else {{
                return XDP_PASS;
            }}
        }}
        if (nexthdr != IPPROTO_TCP)
            return XDP_PASS;
        struct tcphdr *tcph = l4;
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;

        __u16 dport = bpf_ntohs(tcph->dest);
        if (!is_monitored_port(dport))
            return XDP_PASS;

        struct ipv6_key key = {{}};
        __builtin_memcpy(key.addr, &ip6h->saddr, 16);
        if (bpf_map_lookup_elem(&allow_relay_v6, &key))
            return XDP_PASS;

        __u64 *drops = bpf_map_lookup_elem(&blocked_v6, &key);
        if (drops) {{
            __sync_fetch_and_add(drops, 1);
            return XDP_DROP;
        }}

        if (tcph->syn && !tcph->ack) {{
            __u64 now = bpf_ktime_get_ns();
            struct bucket_state *st = bpf_map_lookup_elem(&syn_bucket_v6, &key);
            if (!st) {{
                struct bucket_state init = {{ .last_ns = now, .tokens = SYN_BURST - 1 }};
                bpf_map_update_elem(&syn_bucket_v6, &key, &init, BPF_ANY);
                return XDP_PASS;
            }}
            if (!consume_token(st, now))
                return XDP_DROP;
        }}
        return XDP_PASS;
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "Dual BSD/GPL";
"""


@dataclass(frozen=True)
class ShieldEnforcementSummary:
    """Outcome record of one active built-in shield reconciliation pass."""

    backend: str
    dry_run: bool
    consensus_synced: bool
    added_bans: tuple[str, ...]
    cleared_bans: int
    active_ban_count: int
    skipped_protected: int
    payload_preview: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "backend": self.backend,
            "dry_run": self.dry_run,
            "consensus_synced": self.consensus_synced,
            "added_bans": list(self.added_bans),
            "cleared_bans": self.cleared_bans,
            "active_ban_count": self.active_ban_count,
            "skipped_protected": self.skipped_protected,
            "payload_preview": list(self.payload_preview),
        }


def _default_command_runner(argv: list[str], stdin_payload: str) -> None:
    """Execute privileged nftables or bpftool batch safely without a shell."""
    proc = subprocess.run(
        argv,
        input=stdin_payload,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    if proc.returncode == 0:
        return
    # bpftool batch aborts on map delete ENOENT if LRU_HASH already evicted the key;
    # fall back to per-line execution ignoring ENOENT on map delete so bans never deadlock.
    if argv and argv[0] == "bpftool" and "No such file or directory" in (proc.stderr or ""):
        for line in stdin_payload.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            sub = subprocess.run(
                ["bpftool", *parts],
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
            if sub.returncode != 0:
                if parts[:2] == ["map", "delete"] and "No such file or directory" in (sub.stderr or ""):
                    continue
                raise subprocess.CalledProcessError(sub.returncode, ["bpftool", *parts], sub.stdout, sub.stderr)
        return
    raise subprocess.CalledProcessError(proc.returncode, argv, proc.stdout, proc.stderr)


class ShieldController:
    """Built-in adaptive kernel enforcer driving nftables or pinned XDP/eBPF maps safely."""

    def __init__(
        self,
        ports: set[int],
        consensus_ips: Iterable[str],
        backend: str = "auto",
        dry_run: bool = False,
        ban_ttl_seconds: int = 1800,
        flood_threshold: int = 25,
        consensus_sync_interval: float = 600.0,
        bpf_pin_dir: str = "/sys/fs/bpf/relaysentry",
        allow_cidrs: Iterable[str] = (),
        command_runner: Callable[[list[str], str], None] | None = None,
        backend_detector: Callable[[], str] | None = None,
    ) -> None:
        if backend not in ("auto", "nft", "xdp"):
            raise ValueError(f"Unsupported shield backend: {backend}")
        if ban_ttl_seconds <= 0:
            raise ValueError("ban_ttl_seconds must be > 0")
        sorted_ports = {p for p in ports if 1 <= p <= 65535}
        if not sorted_ports:
            raise ValueError("At least one valid TCP port (1..65535) is required")

        self.ports = sorted_ports
        self.dry_run = bool(dry_run)
        self.ban_ttl_seconds = int(ban_ttl_seconds)
        self.flood_threshold = max(1, int(flood_threshold))
        self.consensus_sync_interval = max(10.0, float(consensus_sync_interval))
        self.bpf_pin_dir = _validate_pin_dir(bpf_pin_dir)
        self._runner = command_runner or _default_command_runner
        self._backend_detector = backend_detector
        self.backend = self._resolve_backend(backend)

        self.consensus_ips: set[str] = set()
        for raw_ip in consensus_ips:
            try:
                self.consensus_ips.add(ipaddress.ip_address(raw_ip).compressed)
            except ValueError:
                continue

        self.allow_networks = tuple(
            ipaddress.ip_network(cidr.strip(), strict=False)
            for cidr in allow_cidrs
            if cidr and cidr.strip()
        )
        self.active_bans: dict[str, float] = {}
        self._last_consensus_sync: float | None = None
        self._had_non_normal: bool = False
        self.last_summary: ShieldEnforcementSummary | None = None

    def update_consensus(self, consensus_ips: Iterable[str]) -> None:
        """Refresh the in-memory Consensus allowlist and schedule immediate kernel re-sync."""
        refreshed: set[str] = set()
        for raw_ip in consensus_ips:
            try:
                refreshed.add(ipaddress.ip_address(raw_ip).compressed)
            except ValueError:
                continue
        if refreshed != self.consensus_ips:
            self.consensus_ips = refreshed
            self._last_consensus_sync = None

    def _resolve_backend(self, requested: str) -> str:
        if requested != "auto":
            if not self.dry_run and shutil.which("nft" if requested == "nft" else "bpftool") is None:
                raise RuntimeError(f"Required shield binary '{requested}' is not installed in PATH")
            return requested
        if self._backend_detector is not None:
            return self._backend_detector()
        if shutil.which("bpftool"):
            try:
                if Path(f"{self.bpf_pin_dir}/blocked_v4").exists():
                    return "xdp"
            except OSError:
                pass
        if shutil.which("nft"):
            return "nft"
        if self.dry_run:
            return "nft"
        raise RuntimeError(
            "No live shield backend available (install nftables 'nft' or attach XDP with 'bpftool', or use --shield-dry-run)"
        )

    def _is_safe_ban_candidate(self, raw_ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        try:
            addr = ipaddress.ip_address(raw_ip)
        except ValueError:
            return None
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
            return None
        if addr.compressed in self.consensus_ips:
            return None
        if any(addr in net for net in self.allow_networks):
            return None
        return addr

    def _apply(self, payload: str) -> None:
        if not payload.strip() or self.dry_run:
            return
        cmd = ["nft", "-f", "-"] if self.backend == "nft" else ["bpftool", "batch", "file", "-"]
        self._runner(cmd, payload)

    def reconcile(
        self,
        effective_severity: str,
        candidate_flooder_ips: Iterable[str],
        now_monotonic: float | None = None,
    ) -> ShieldEnforcementSummary:
        """Reconcile consensus allowlists, active flooder bans, and hysteresis recovery."""
        now = time.monotonic() if now_monotonic is None else float(now_monotonic)
        payload_chunks: list[str] = []
        consensus_synced = False
        new_sync_ts = self._last_consensus_sync

        if self._last_consensus_sync is None or (now - self._last_consensus_sync) >= self.consensus_sync_interval:
            if self.backend == "nft":
                chunk = generate_nft_consensus_sync(
                    self.consensus_ips,
                    self.ports,
                    conn_limit=self.flood_threshold,
                    ban_timeout=f"{self.ban_ttl_seconds}s",
                    allow_cidrs=[str(n) for n in self.allow_networks],
                )
            else:
                xdp_allow = set(self.consensus_ips)
                for net in self.allow_networks:
                    if net.prefixlen == net.max_prefixlen:
                        xdp_allow.add(net.network_address.compressed)
                chunk = generate_xdp_map_sync(xdp_allow, pin_dir=self.bpf_pin_dir)
            payload_chunks.append(chunk)
            new_sync_ts = now
            consensus_synced = True

        expired_ips = [ip for ip, deadline in self.active_bans.items() if now >= deadline]
        staged_bans = {ip: dl for ip, dl in self.active_bans.items() if ip not in expired_ips}

        cleared_count = 0
        if effective_severity == "NORMAL":
            to_clear = sorted(set(staged_bans.keys()) | set(expired_ips))
            if to_clear or self._had_non_normal:
                if self.backend == "nft":
                    if to_clear:
                        if any(":" not in ip for ip in to_clear):
                            payload_chunks.append("flush set inet relaysentry_shield tor_ddos4")
                        if any(":" in ip for ip in to_clear):
                            payload_chunks.append("flush set inet relaysentry_shield tor_ddos6")
                    else:
                        payload_chunks.append("flush set inet relaysentry_shield tor_ddos4")
                        payload_chunks.append("flush set inet relaysentry_shield tor_ddos6")
                elif to_clear:
                    payload_chunks.append(
                        generate_xdp_map_sync((), pin_dir=self.bpf_pin_dir, unblock_ips=to_clear)
                    )
                cleared_count = len(to_clear)
                staged_bans.clear()
                self._had_non_normal = False
        elif expired_ips and self.backend == "xdp":
            payload_chunks.append(generate_xdp_map_sync((), pin_dir=self.bpf_pin_dir, unblock_ips=expired_ips))
            cleared_count = len(expired_ips)

        if effective_severity != "NORMAL":
            self._had_non_normal = True

        added_bans: list[str] = []
        skipped_protected = 0
        if effective_severity != "NORMAL":
            v4_new: list[str] = []
            v6_new: list[str] = []
            for raw_ip in candidate_flooder_ips:
                addr = self._is_safe_ban_candidate(raw_ip)
                if addr is None:
                    skipped_protected += 1
                    continue
                canonical = addr.compressed
                if canonical in staged_bans:
                    continue
                added_bans.append(canonical)
                staged_bans[canonical] = now + self.ban_ttl_seconds
                if addr.version == 4:
                    v4_new.append(canonical)
                else:
                    v6_new.append(canonical)

            if added_bans:
                if self.backend == "nft":
                    if v4_new:
                        elems4 = ", ".join(f"{ip} timeout {self.ban_ttl_seconds}s" for ip in v4_new)
                        payload_chunks.append(f"add element inet relaysentry_shield tor_ddos4 {{ {elems4} }}")
                    if v6_new:
                        elems6 = ", ".join(f"{ip} timeout {self.ban_ttl_seconds}s" for ip in v6_new)
                        payload_chunks.append(f"add element inet relaysentry_shield tor_ddos6 {{ {elems6} }}")
                else:
                    payload_chunks.append(
                        generate_xdp_map_sync((), blocked_ips=added_bans, pin_dir=self.bpf_pin_dir)
                    )

        combined_payload = "\n".join(c for c in payload_chunks if c.strip())
        self._apply(combined_payload)
        self._last_consensus_sync = new_sync_ts
        self.active_bans = staged_bans

        preview = tuple(line for line in combined_payload.splitlines()[:6] if line)
        summary = ShieldEnforcementSummary(
            backend=self.backend,
            dry_run=self.dry_run,
            consensus_synced=consensus_synced,
            added_bans=tuple(added_bans),
            cleared_bans=cleared_count,
            active_ban_count=len(self.active_bans),
            skipped_protected=skipped_protected,
            payload_preview=preview,
        )
        self.last_summary = summary
        return summary
