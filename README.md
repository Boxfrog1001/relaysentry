# RelaySentry

**Privacy-preserving real-time DoS triage and consensus peer attribution for Tor relay operators.**

`RelaySentry` correlates Linux kernel socket tables (`/proc/net/tcp`, `/proc/net/tcp6`), Tor's local Prometheus `MetricsPort`, and optional `ControlPort` (`GETINFO orconn-status`) telemetry against the public Tor Consensus — giving `Guard`, `Middle`, `Exit`, and `HSDir` operators immediate visibility during `BEGIN_DIR`, `CREATE2`, or `SYN` floods **without logging honest Tor client IPs**.

---

## Why RelaySentry Exists (Threat Model Boundaries)

When a Tor relay hits overload (`dropped ntor onionskins`, OOM invocations, or socket exhaustion), operators need to answer one immediate question:
> **Is this flood arriving from rogue/abused Consensus Relays (`AS` / `effective_family` clusters), or from non-relay direct IP floods hitting our `ORPort` / `DirPort`?**

> [!IMPORTANT]
> **Strict Architectural & Privacy Boundaries**
> * **Immediate Peer Scope Only:** Tor's onion encryption intentionally ensures a relay only knows its immediate TCP peer. `RelaySentry` attributes **immediate** consensus relays vs. non-relay flooders hitting your listening ports; it does **not** and **cannot** trace backward across upstream Tor hops to origin clients.
> * **Strict Client Anonymity Default:** All non-consensus peers are masked in RAM using an ephemeral `os.urandom(32)` HMAC-SHA256 key (`anon#<16-hex>`). Non-relay IPs are **never** written to disk.
> * **Threshold-Gated Emergency Reveal:** Even when an operator explicitly passes `--reveal-flooders` to draft `nftables` rate limits during an active DoS wave, peers below `--flood-threshold` (default `25` concurrent sockets) **stay masked** — keeping normal 1–4 socket Tor users protected.

---

## Features

* **Zero-Subprocess Kernel Socket Telemetry & Overload Stride:** Reads `/proc/net/tcp` and `/proc/net/tcp6` directly in pure Python (64 MiB read cap), tracking active `ESTABLISHED`, `SYN_SENT`, and `SYN_RECV` sockets (excluding `LISTEN`, `TIME_WAIT`, and closing states) and `rx_queue`/`tx_queue` byte depths, with automatic `1-in-16` stride sampling above `--max-exact-sockets` (`50000`) and a minimum raw sample floor so low-socket clients are never misattributed under overload.
* **Built-In Adaptive Shield Engine & Active Enforcement (`--enforce-shield`):** Combines a 3-state attack hysteresis hold (`--hysteresis-seconds`), anonymized HMAC-bucket Shannon entropy flood-shape classification (`CONCENTRATED_SOURCE` vs `DISTRIBUTED_BOTNET`), bounded 64-tick ring history, `torrc` `DoSBeginDir*` / Equi-X PoW & kernel `sk_buff` (`net.core.high_order_alloc_disable=1`) guidance, atomic per-IP dual-stack consensus-safe `nftables` (`--emit-nft-consensus`), `bpftool` XDP map sync (`--emit-xdp-sync`), and a compilable dual-stack `eBPF/XDP` SYN token-bucket shield (`--emit-xdp-c`). When started with `--enforce-shield`, `ShieldController` refreshes Consensus allowlists in `--watch` mode, blocks verified high-socket flooders (`--ban-ttl`, strictly skipping Consensus relays, loopback, and `--allow-cidr` — full CIDRs in `nft` interval sets and `/32`/`/128` hosts in XDP maps), and flushes temporary bans on recovery (`--shield-dry-run` evaluates logic locally without requiring root or invoking `nft`/`bpftool`).
* **Tor `MetricsPort` & Thunderstorm Integration:** Parses official Prometheus counters (`tor_relay_connections`, `tor_relay_load_onionskins_total`, `tor_relay_load_oom_bytes_total`, `tor_relay_load_socket_total`, `tor_relay_load_tcp_exhaustion*`, `tor_relay_dos_total{type="begindir_*|circuit_*|conn_rejected"}`, and `tor_relay_streams_total{cmd="BEGIN_DIR"}`) with non-crashing timeout resilience (`--metrics-timeout` -> `METRICS_PORT_UNRESPONSIVE`) and half-open `BEGIN_DIR` event-loop stall detection (`HALF_OPEN_BEGIN_DIR_BYPASS_SUSPECTED`).
* **Tor `ControlPort` Cross-Check:** Supports bounded 32-byte cookie authentication (`--control-cookie` / `--control-port`) to fetch `GETINFO orconn-status` and correlate live peer OR circuits.
* **Consensus Relay & Family Rollup:** Indexes field-filtered Onionoo `/details` (compressed via `gzip`, supporting `--proxy`, `--no-cache` amnesic mode, atomic `0600` cache files reused for a 1-hour TTL, and `--refresh` to force a live reload) to group relays by `effective_family` or `AS + /24` — **or** a relay's local v3 `cached-consensus` (`--consensus-file /var/lib/tor/cached-consensus`, which requires `debian-tor`/root read access and groups relays under `AS_LOCAL` + `/24` because Tor v3 consensus files omit ASN and family metadata).
* **Zero Runtime Dependencies:** Pure Python 3.10+ standard library.

---

## Quick Start

### 1. Run Offline Verification Suite & 4-Stage Thunderstorm Simulator
```bash
python3 test/verify_relaysentry.py
python3 test/simulate_thunderstorm.py
```

### 2. Live Relay Monitoring (Strict Privacy Default)
Ensure your local `torrc` binds `MetricsPort` safely to localhost:
```text
MetricsPort 127.0.0.1:9035
MetricsPortPolicy accept 127.0.0.1
```

Run a live triage pass (all non-relay IPs masked with ephemeral session HMAC):
```bash
./bin/relaysentry \
  --port 9001 \
  --port 9030 \
  --metrics-url http://127.0.0.1:9035/metrics \
  --no-cache \
  --watch 5
```

### 3. Active Non-Relay Flooder Triage (RAM-Only Above Threshold)
```bash
./bin/relaysentry \
  --port 9001 \
  --metrics-url http://127.0.0.1:9035/metrics \
  --reveal-flooders \
  --flood-threshold 25 \
  --emit-nft-hints
```
*Note: Only non-relay peers holding `>= 25` concurrent sockets are revealed in live terminal output; consensus relays are flagged with Fingerprint/ASN/`effective_family` rather than global firewall blocks so Tor mesh routing is not partitioned.*

### 4. Built-In Adaptive Enforcement (`nftables` or `XDP/eBPF`)
Dry-run the built-in shield locally against live consensus + kernel sockets without modifying firewall state (non-relay IPs stay HMAC-masked unless `--reveal-flooders` is also passed):
```bash
./bin/relaysentry --port 9001 --port 9030 --enforce-shield --shield-dry-run --watch 5
```

Smoke-check the generated `nftables` ruleset against your live kernel (`CAP_NET_ADMIN` / `sudo`, `nftables >= 0.9.3`, `nf_conntrack` module loaded) before applying:
```bash
./bin/relaysentry --port 9001 --port 9030 --allow-cidr 198.51.100.0/24 --emit-nft-consensus | sudo nft -c -f -
./bin/relaysentry --port 9001 --port 9030 --allow-cidr 198.51.100.0/24 --emit-nft-consensus | sudo nft -f -
```

Enforce live via `nftables` (`allow_net4/6` + `known_relays4/6` + per-IP dynamic `tor_syn4/6` + bounded teardown `tor_fin4/6` + auto-expiring `tor_ddos4/6`; Tor relays, loopback, and `--allow-cidr` stay exempt):
```bash
sudo ./bin/relaysentry --port 9001 --port 9030 --allow-cidr 198.51.100.0/24 --enforce-shield --shield-backend nft --ban-ttl 1800 --watch 5
```

Or deploy the dual-stack XDP/eBPF NIC-ring filter (requires `clang`, `libbpf-dev`, kernel headers, `bpftool >= 5.9`, mounted `bpffs` at `/sys/fs/bpf`, and NIC driver XDP support; replace `<IFACE>` with your external interface name):
```bash
./bin/relaysentry --port 9001 --port 9030 --emit-xdp-c > relaysentry_xdp.c
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c relaysentry_xdp.c -o relaysentry_xdp.o
sudo bpftool prog load relaysentry_xdp.o /sys/fs/bpf/relaysentry_xdp_prog pinmaps /sys/fs/bpf/relaysentry
sudo bpftool net attach xdp pinned /sys/fs/bpf/relaysentry_xdp_prog dev <IFACE>
./bin/relaysentry --port 9001 --port 9030 --emit-xdp-sync | sudo bpftool batch file -
sudo ./bin/relaysentry --port 9001 --port 9030 --enforce-shield --shield-backend xdp --watch 5
```

*Note: Root `sudo` runs cache Onionoo JSON under `/root/.cache/relaysentry/`, whereas unprivileged dry-runs cache under `$HOME/.cache/relaysentry/`. On hardened hosts without `nf_conntrack`, use `--shield-backend xdp` instead of `conntrack`-based nftables rules.*

---

## Project Layout
* [`bin/relaysentry`](bin/relaysentry) — CLI launcher
* [`src/relaysentry.py`](src/relaysentry.py) — CLI entrypoint & watch/JSON reporter
* [`src/privacy_vault.py`](src/privacy_vault.py) — Volatile `os.urandom(32)` HMAC anonymizer & threshold gate
* [`src/telemetry_procfs.py`](src/telemetry_procfs.py) — Linux `/proc/net/tcp` + `/proc/net/tcp6` decoder & overload stride sampler
* [`src/telemetry_tor.py`](src/telemetry_tor.py) — Bounded `MetricsPort` & `ControlPort` readers
* [`src/consensus_index.py`](src/consensus_index.py) — Onionoo/Consensus indexer (`0600` cache / `--no-cache`)
* [`src/correlator.py`](src/correlator.py) — Multi-signal DoS triage & family/AS rollup engine
* [`src/shield_engine.py`](src/shield_engine.py) — Hysteresis, entropy flood classifier, consensus `nft` allowlist, `torrc` PoW & XDP/eBPF C shield
* [`doc/THREAT_MODEL_AND_SPECS.md`](doc/THREAT_MODEL_AND_SPECS.md) — Architectural & Tor specification ground truth
* [`doc/ENGINEERING_STORY.md`](doc/ENGINEERING_STORY.md) — Build, Thunderstorm reconstruction & dual Goldfish hostile audit story
* [`test/verify_relaysentry.py`](test/verify_relaysentry.py) — 10-suite offline + loopback sandbox testbench
* [`test/simulate_thunderstorm.py`](test/simulate_thunderstorm.py) — 4-stage live Thunderstorm & half-open bypass simulator
