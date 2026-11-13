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

* **Linux Kernel `procfs` (`/proc/net/tcp`, `/proc/net/tcp6`):** Direct pure-Python decoding of kernel TCP states (`ESTABLISHED`, `SYN_RECV`, `CLOSE_WAIT`, `TIME_WAIT`) and per-socket `rx_queue` / `tx_queue` bytes on local `ORPort` / `DirPort` without invoking shell commands.
* **Tor `MetricsPort` (Prometheus Text Exposition, `src/feature/relay/relay_metrics.c`):**
  * `tor_relay_connections` (`type`, `direction`, `state`, `family`)
  * `tor_relay_load_onionskins_total` (`type`, `action` = `processed` / `dropped`)
  * `tor_relay_load_oom_bytes_total`
  * `tor_relay_load_socket_total`
  * `tor_relay_load_tcp_exhaustion_total` / `tor_relay_load_global_rate_limit_reached_total`
* **Tor `ControlPort` (`control-spec`):**
  * `GETINFO orconn-status` (`LongName SP ORStatus`) using bounded cookie/password authentication.
* **Tor Consensus (`Onionoo /details` / local JSON):**
  * Parses canonical IPv4 and bracket-stripped compressed IPv6 `or_addresses`, `dir_address`, `effective_family` (normalized uppercase `$`-stripped 40-hex fingerprints), `flags`, `as`, `as_name`, `consensus_weight`, and `version`.
