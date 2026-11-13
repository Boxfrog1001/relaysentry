# Engineering Story: Building, Breaking, and Hardening RelaySentry (`v0.1.0` -> `v0.3.1`)

## Why We Built This

While upstream Tor engineers work through longer-term protocol and C-level patches for ongoing relay DoS waves (`BEGIN_DIR` "Thunderstorm" resource exhaustion, post-`0.4.9.16` half-open `BEGIN_DIR` stalls, `MetricsPort` saturation, and VPS `sk_buff` slab bloat), individual relay operators still face a brutal day-to-day operational gap: when a relay drops `ntor` onionskins or hits `tor` OOM, you need a zero-bloat mitigation right now that **separates non-relay flooders from real Consensus relays and 1–4 socket Tor users** without logging Tor client IPs to disk.

`RelaySentry` started from a single rule: **do triage and mitigation safely enough that an operator won't accidentally firewall the Tor network or brick their own box during a panic.**

---

## Stage 1 — Consensus Attribution Without Client Surveillance (`v0.1.0`)

Most ad-hoc `netstat` / `ss` scripts either dump raw peer IPs straight to terminal/logs or block top-socket peers blindly (taking down heavy Consensus relays and Directory Authorities in the process).

We built the foundation around three hard invariants in pure Python 3.10+ stdlib:
* **Ephemeral RAM-only client privacy (`src/privacy_vault.py`):** Non-relay IPs are keyed per process via `os.urandom(32)` HMAC-SHA256 (`anon#<16-hex>`) and never touch disk. Even with `--reveal-flooders`, peers below `--flood-threshold` stay masked.
* **Direct `/proc/net/tcp[6]` telemetry (`src/telemetry_procfs.py`):** Zero subprocesses (`ss`/`netstat` skipped) with strict bounded parsing.
* **Public Consensus indexing (`src/consensus_index.py`):** Field-filtered gzip Onionoo `/details` + local Tor `cached-consensus` fallback with CWE-409 streaming gzip bounds, `0600` atomic caching, and SSRF redirect locks.

---

## Stage 2 — Reconstructing the Real Thunderstorm Attack (`v0.2.0` -> `v0.3.0`)

Before shipping kernel automation, we reproduced the attack mechanics reported by Tor operators in a local 4-stage simulator ([`test/simulate_thunderstorm.py`](../test/simulate_thunderstorm.py)):
1. **Classic `BEGIN_DIR` Thunderstorm:** Rising `tor_relay_dos_total{type="begindir_*"}` and `tor_relay_streams_total{cmd="BEGIN_DIR"}` alongside `ntor` drops and heavy peer queues.
2. **Post-`0.4.9.16` Half-Open `BEGIN_DIR` Bypass:** Flooders stalling sockets just before HTTP `GET` completion so `begindir_*_rejected` stays `0` while kernel socket queues fill.
3. **Full Event-Loop Saturation (`MetricsPort` / `ControlPort` Timeouts):** When `tor`'s main loop saturates, naive monitoring scripts crash with `TimeoutError`. We taught `RelaySentry` to survive `MetricsPort`/`ControlPort` stalls using procfs fallback and emit `HALF_OPEN_BEGIN_DIR_BYPASS_SUSPECTED`.
4. **Adaptive Shield (`src/shield_engine.py`):** Built `DefenseStateMachine` (hysteresis hold), anonymized Shannon-entropy flood classification (`CONCENTRATED_SOURCE` vs `DISTRIBUTED_BOTNET`), `ShieldController` driving dual-stack `nftables` (`known_relays4/6` + auto-expiring `tor_ddos4/6`) and `XDP/eBPF` (`relaysentry_xdp.c` + `bpftool batch` map sync).

All 10 test suites passed on `v0.3.0`—**and then we refused to trust our own build.**

---

## Stage 3 — Dual Cold-Context Audits ("Goldfish" Code & Hostile Critiques)

Even with `10/10` local tests green, we ran **two completely fresh, zero-history audit passes** (`egm-codebase-details` for doc-to-code truth + `egm-design` as a hostile production critic) before trusting it for live Linux relays.

The cold audits caught real, deployment-breaking flaws that green unit tests missed:

1. **Global vs. Per-IP `nftables` Rate Limit (`Blocker`):**
   `generate_nft_consensus_sync()` emitted a rule-global `limit rate over 10/second burst 20 packets` instead of a per-IP dynamic set. On any busy Tor relay seeing `>10` new non-relay connections per second across honest Tor clients combined, that single rule would have exhausted globally and auto-banned honest 1-socket Tor users into `tor_ddos4/6`.
2. **XDP `bpftool batch` `ENOENT` Deadlock Under Eviction (`Blocker`):**
   `blocked_v4`/`blocked_v6` use `BPF_MAP_TYPE_LRU_HASH`. Under >65k floods, the kernel LRU evicts old keys—causing `bpftool batch file -` on expired `map delete` keys to abort with `ENOENT`, which threw `CalledProcessError` before `self.active_bans` cleared and deadlocked subsequent enforcement ticks forever.
3. **`--allow-cidr` Missing from Kernel Rules (`Blocker`):**
   Operator `--allow-cidr` exemptions checked only Python-side `ShieldController._is_safe_ban_candidate()`, not kernel `nft` or XDP allowlists.
4. **Silent Stale Consensus in `--watch` + Cold `--offline` Trap (`Blocker`):**
   Long-running `--watch` daemons never refreshed their startup Consensus snapshot (risking banning newly onboarded relays), and `--offline --enforce-shield` without cache initialized with an empty relay allowlist.
5. **Silent Privacy Leak on `--enforce-shield --shield-dry-run` (`Major`):**
   Dry-run enforcement implicitly forced `reveal_flooders=True`, printing raw flooder IPs even when `--reveal-flooders` wasn't passed.
6. **`TIME_WAIT` Accounting, `1-in-16` Stride Math & Per-CPU XDP Amplification (`Major`):**
   Lingering `TIME_WAIT` sockets counted toward socket totals, a 2-socket peer under `1-in-16` stride scaling could multiply `2 * 16 = 32 >= 25`, per-CPU XDP SYN buckets multiplied attacker burst limits by core count, and IPv6 extension headers bypassed `nexthdr != IPPROTO_TCP`.

---

## Stage 4 — `v0.3.1` Mitigation Release

Every single one of those findings is patched in `v0.3.1`:
* Per-IP `tor_syn4`/`tor_syn6` (`flags dynamic, timeout`), explicit `allow_net4`/`allow_net6` (`flags interval` + loopback + `--allow-cidr`), `timeout 120s` on `connlimit4/6`, idempotent table setup across `--ban-ttl` edits, and automatic `NORMAL` recovery set flushes.
* Line-by-line `bpftool` `ENOENT`-tolerant cleanup on LRU-evicted keys, global `BPF_MAP_TYPE_LRU_HASH` SYN buckets across cores, and a bounded IPv6 extension-header walker in XDP C.
* Strict `TIME_WAIT`/closing exclusion in `/proc/net/tcp[6]`, `>= 3` raw sample floor under stride sampling, periodic Consensus refresh in `--watch`, empty-Consensus live-shield safety abort under `--offline`, and HMAC-masked `added_bans` output unless `--reveal-flooders` is explicitly set.

**Practical takeaway:** `RelaySentry` isn't a replacement for upstream Tor C fixes—it's a hardened, battle-audited shield and forensic triage bridge designed to keep real relay operators online safely until the next upstream Tor mitigation lands cleanly across the network.
