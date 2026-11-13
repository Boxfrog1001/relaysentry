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

* **Zero-Subprocess Kernel Socket Telemetry & Overload Stride:** Reads `/proc/net/tcp` and `/proc/net/tcp6` directly in pure Python, tracking `ESTABLISHED`, `SYN_RECV`, `CLOSE_WAIT`, and `rx_queue`/`tx_queue` byte depths, with automatic `1-in-16` stride sampling above `--max-exact-sockets` (`50000`) so floods do not exhaust analysis RAM/CPU.
* **Built-In Adaptive Shield Engine & Active Enforcement (`--enforce-shield`):** Combines a 3-state attack hysteresis hold (`--hysteresis-seconds`), anonymized HMAC-bucket Shannon entropy flood-shape classification (`CONCENTRATED_SOURCE` vs `DISTRIBUTED_BOTNET`), bounded 64-tick ring history, `torrc` `DoSBeginDir*` / Equi-X PoW & kernel `sk_buff` (`net.core.high_order_alloc_disable=1`) guidance, atomic dual-stack consensus-safe `nftables` (`--emit-nft-consensus`), `bpftool` XDP map sync (`--emit-xdp-sync`), and a compilable dual-stack `eBPF/XDP` SYN token-bucket shield (`--emit-xdp-c`). When started with `--enforce-shield`, `ShieldController` syncs consensus allowlists, blocks verified high-socket flooders (`--ban-ttl`, strictly skipping Consensus relays and `--allow-cidr`), and flushes temporary bans after hysteresis recovery (`--shield-dry-run` supported without kernel mutation).
* **Tor `MetricsPort` & Thunderstorm Integration:** Parses official Prometheus counters (`tor_relay_connections`, `tor_relay_load_onionskins_total`, `tor_relay_load_oom_bytes_total`, `tor_relay_load_socket_total`, `tor_relay_load_tcp_exhaustion*`, `tor_relay_dos_total{type="begindir_*|circuit_*|conn_rejected"}`, and `tor_relay_streams_total{cmd="BEGIN_DIR"}`) with non-crashing timeout resilience (`--metrics-timeout` -> `METRICS_PORT_UNRESPONSIVE`) and half-open `BEGIN_DIR` event-loop stall detection (`HALF_OPEN_BEGIN_DIR_BYPASS_SUSPECTED`).
* **Tor `ControlPort` Cross-Check:** Supports bounded 32-byte cookie/password authentication to fetch `GETINFO orconn-status` and correlate live peer OR circuits.
* **Consensus Relay & Family Rollup:** Indexes field-filtered Onionoo `/details` (compressed via `gzip`, supporting `--proxy`, `--no-cache` amnesic mode, atomic `0600` cache files reused for a 1-hour TTL, and `--refresh` to force a live reload) **or** a relay's own local `cached-consensus` (`--consensus-file /var/lib/tor/cached-consensus`) to group relay flood traffic individually and by `effective_family` or `AS + /24`.
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
Dry-run the built-in shield locally against live consensus + kernel sockets without modifying firewall state:
```bash
./bin/relaysentry --port 9001 --port 9030 --enforce-shield --shield-dry-run --watch 5
```

Enforce live via `nftables` (`known_relays4`/`known_relays6` + auto-expiring `tor_ddos4`/`tor_ddos6`, SSH/management & Tor relays stay untouched):
```bash
sudo ./bin/relaysentry --port 9001 --port 9030 --enforce-shield --shield-backend nft --ban-ttl 1800 --watch 5
```

Or deploy the dual-stack XDP/eBPF NIC-ring filter (`bpftool` map sync + `--enforce-shield --shield-backend xdp`):
```bash
./bin/relaysentry --port 9001 --port 9030 --emit-xdp-c > relaysentry_xdp.c
clang -O2 -g -target bpf -c relaysentry_xdp.c -o relaysentry_xdp.o
sudo bpftool prog load relaysentry_xdp.o /sys/fs/bpf/relaysentry_xdp_prog pinmaps /sys/fs/bpf/relaysentry
sudo bpftool net attach xdp pinned /sys/fs/bpf/relaysentry_xdp_prog dev eth0
./bin/relaysentry --port 9001 --emit-xdp-sync | sudo bpftool batch file -
sudo ./bin/relaysentry --port 9001 --port 9030 --enforce-shield --shield-backend xdp --watch 5
```

You can also export standalone `nftables` consensus rules cleanly:
```bash
./bin/relaysentry --port 9001 --port 9030 --emit-nft-consensus | sudo nft -f -
```

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
* [`test/verify_relaysentry.py`](test/verify_relaysentry.py) — 10-suite offline + loopback sandbox testbench
* [`test/simulate_thunderstorm.py`](test/simulate_thunderstorm.py) — 4-stage live Thunderstorm & half-open bypass simulator
