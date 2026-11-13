# RelaySentry: Tor Threat Model, Privacy Invariants & Protocol Ground Truth

## 1. What RelaySentry Does (and What It Explicitly Cannot Do)

Tor's onion routing guarantees that an intermediate relay, Guard, or HSDir only ever observes its **immediate network peer** on each TCP/TLS link:

* **Client -> Guard:** A Guard's incoming TCP connections may be real Tor users or direct TCP/ORPort DoS flooders.
* **Relay -> Relay (Middle / Guard / Exit / HSDir):** Incoming OR connections (`ORPort`) and directory tunnels may originate from **other consensus relays** forwarding circuits or `BEGIN_DIR` / `CREATE2` floods.

**RelaySentry is strictly a relay-side DoS telemetry & immediate-peer attribution tool.**
* It **DOES** attribute immediate flooding peers against the public Tor Consensus (identifying rogue/abused **Consensus Relays** by Fingerprint, Nickname, `effective_family`, ASN, Flags, and `/24` subnet) while monitoring the local Tor daemon's Prometheus `MetricsPort` and `ControlPort` (`GETINFO orconn-status`).
* It **DOES NOT** (and architecturally **cannot**) de-anonymize multi-hop Tor clients behind upstream relays, nor does it attempt cross-hop correlation.

---

## 2. Cryptographic Tor-User Privacy Invariants

Any tool inspecting a Tor relay's socket table risks recording honest Tor users' IP addresses. RelaySentry enforces four hard technical safeguards:

1. **Zero Disk Persistence of Non-Relay Peers:** Non-consensus peer IPs are never written to caches, JSON snapshots, or logs.
2. **Ephemeral Per-Run CSPRNG HMAC (`os.urandom(32)`):** All non-relay peers are mapped in volatile RAM to an ephemeral token (`anon#<16-hex>`) keyed by an in-memory 256-bit random key generated at process startup and discarded on exit. An operator can still see whether 500 floods came from 1 bot (`anon#a1b2...` x 500) vs 500 distinct IPs without ever seeing a single honest client IP.
3. **Threshold-Gated Opt-In (`--reveal-flooders` + `--flood-threshold`):** Even when an operator explicitly passes `--reveal-flooders` during a live emergency to write an `nftables` rate-limit rule, RelaySentry **still masks** any non-relay IP holding fewer than `--flood-threshold` concurrent sockets (default: `25`). Normal Tor users (1–4 connections) remain protected even in emergency mode.
4. **Amnesic / Cache Hardening:** Consensus directory caches default to strict `0600` permissions (`os.open` atomic mode) and support `--no-cache` RAM-only operation alongside `--proxy`.

---

## 3. Canonical Tor Telemetry & Metrics Ground Truth

RelaySentry consumes only official Tor operator interfaces:

* **Linux Kernel `procfs` (`/proc/net/tcp`, `/proc/net/tcp6`):** Direct pure-Python decoding (bounded to `64 MiB` on live reads) of active TCP states (`ESTABLISHED`, `SYN_SENT`, `SYN_RECV`, and `NEW_SYN_RECV` (`0C`) — excluding `LISTEN`, `TIME_WAIT`, `CLOSE_WAIT`, and closing states) and per-socket `rx_queue` / `tx_queue` bytes on local `ORPort` / `DirPort` without invoking shell commands. Above `--max-exact-sockets` (default `50000`), deterministic `1-in-16` stride sampling engages with a minimum raw sample floor before reveal, ban, or `NONRELAY_PEER_FLOOD` eligibility.
* **Tor `MetricsPort` (Prometheus Text Exposition, `src/feature/relay/relay_metrics.c`):**
  * `tor_relay_connections` (`type`, `direction`, `state`, `family`)
  * `tor_relay_load_onionskins_total` (`type`, `action` = `processed` / `dropped`)
  * `tor_relay_load_oom_bytes_total`
  * `tor_relay_load_socket_total`
  * `tor_relay_load_tcp_exhaustion_total` / `tor_relay_load_global_rate_limit_reached_total`
  * `tor_relay_dos_total` (`type` = `begindir_*`, `circuit_*`, `conn_rejected`) / `tor_relay_streams_total` (`cmd="BEGIN_DIR"`)
  * *Delta semantics:* Continuous `--watch` runs automatically baseline cumulative counters on the first successful scrape so interval alerts start on the next tick; single-shot (`--watch 0`) scrapes report lifetime process counters when no prior snapshot exists.
* **Tor `ControlPort` (`control-spec`):**
  * `GETINFO orconn-status` (`LongName SP ORStatus`) using bounded 32-byte cookie authentication.
* **Tor Consensus (`Onionoo /details` / local v3 & microdesc files):**
  * Parses canonical IPv4 and bracket-stripped compressed IPv6 `or_addresses`, `dir_address`, `effective_family` (normalized uppercase `$`-stripped 40-hex fingerprints), `flags`, `as`, `as_name`, `consensus_weight`, and `version` from Onionoo `/details`, or reads local `/var/lib/tor/cached-consensus` and `cached-microdesc-consensus` files.

---

## 4. Active Kernel Shield Scope & Beta Operational Boundaries

When explicitly invoked with `--enforce-shield` (or rule generators `--emit-nft-consensus` / `--emit-xdp-c` / `--emit-xdp-sync`), RelaySentry treats Consensus allowlisting and non-persistent cleanup as strict invariants:

* **Bypass Prevention & Priority Exemptions:** Loopback ranges (`127.0.0.0/8`, `::1/128`), active Consensus relay IPs (`known_relays4`/`known_relays6` in `nftables`; `allow_relay_v4`/`allow_relay_v6` in XDP), and operator `--allow-cidr` exemptions are evaluated ahead of dynamic SYN rate-limits and block maps. Full CIDRs are supported in `nftables` interval sets; XDP allowlist sync currently expands `/32` IPv4 and `/128` IPv6 host entries (wider CIDR matching in XDP requires future `BPF_MAP_TYPE_LPM_TRIE` work).
* **Bounded Teardown & Expiry:** Temporary high-socket flooder blocks (`--ban-ttl`) expire cleanly and permit rate-bounded `FIN`/`RST` teardown traffic (`tor_fin4`/`tor_fin6` in `nft`, `syn_bucket_v4/6` in XDP) so closing flood sockets do not pin kernel `ESTABLISHED` entries indefinitely during `NORMAL` hysteresis recovery.
* **Runtime-Only Kernel State (Experimental Beta):** Rules live in the volatile `inet relaysentry_shield` table or pinned `/sys/fs/bpf/relaysentry` maps rather than persistent system firewall configs. Operators should test live changes using `--shield-dry-run` and `nft -c -f -` before deploying in production, noting that `--enforce-shield` without `--watch` clears or installs rules for that single pass only.
