# Changelog

## [0.3.0] - 2026-11-13
### Added
- `BEGIN_DIR` Thunderstorm telemetry & correlation (`src/telemetry_tor.py`, `src/correlator.py`): parses `tor_relay_dos_total{type="begindir_rate_rejected"|"begindir_rejected"|"begindir_hsdir_rejected"|"circuit_rejected"|"circuit_killed_max_cell"|"circuit_killed_max_cell_outq"|"conn_rejected"|"concurrent_conn_rejected"}` and `tor_relay_streams_total{cmd="BEGIN_DIR"}` deltas (`THUNDERSTORM_BEGIN_DIR_FLOOD`, `TOR_CIRCUIT_CELL_DOS_TRIGGERS`).
- Post-`0.4.9.16` half-open `BEGIN_DIR` bypass & event-loop stall detection (`HALF_OPEN_BEGIN_DIR_BYPASS_SUSPECTED`): flags heavy relay kernel socket queue buildup when `begindir_*_rejected == 0` OR when `MetricsPort`/`ControlPort` time out under CPU saturation.
- Non-crashing telemetry resilience (`--metrics-timeout`, default `5.0s`): `--watch` loop catches transient `MetricsPort`/`ControlPort` timeouts, HTTP read aborts, and closed-socket EOF errors cleanly (`METRICS_PORT_UNRESPONSIVE` / `CONTROL_PORT_UNRESPONSIVE`) while preserving previous MetricsPort counter baselines.
- Dual-stack consensus-safe `nftables` generator (`--emit-nft-consensus`): outputs atomic `known_relays4`/`known_relays6` allowlists (protecting Directory Authorities & peers) plus timeout `tor_ddos4`/`tor_ddos6` rate-limit sets, paired with kernel `sk_buff` bloat mitigation guidance (`sysctl -w net.core.high_order_alloc_disable=1`, `DoSBeginDirRateEnabled 1`, `DoSBeginDirLimitEnabled 1`, `NumCPUs 16`, `MaxMemInQueues 2 GB`, emergency `DirCache 0`).
- Built-in adaptive enforcement controller (`ShieldController` via `--enforce-shield`, `--shield-backend {auto,nft,xdp}`, `--shield-dry-run`, `--ban-ttl`, `--bpf-pin-dir`, `--allow-cidr`) and `bpftool batch file -` XDP map emitter (`--emit-xdp-sync`) driving `allow_relay_v4/6` and `blocked_v4/6` (or `nft -f -` `known_relays4/6` + `tor_ddos4/6`) with strict consensus/honest-client/allowlist exemptions and automatic hysteresis de-escalation cleanup.
- 4-stage local Thunderstorm & half-open bypass simulator (`test/simulate_thunderstorm.py`) and 10-suite regression verification (`[TEST 9]` & `[TEST 10]`) in `test/verify_relaysentry.py`.

## [0.2.0] - 2026-11-13
### Added
- Adaptive Defense Shield module (`src/shield_engine.py`): 3-state attack hysteresis controller (`--hysteresis-seconds`), bounded `64`-window ring buffer, anonymized HMAC-bucket Shannon entropy flood-shape classifier (`CONCENTRATED_SOURCE` vs `DISTRIBUTED_BOTNET`), dynamic `torrc`/Equi-X PoW tuning guidance, and pre-conntrack `nftables` `raw prerouting notrack` + rate-limit shield rules.
- Dual-stack Linux XDP/eBPF ingress C filter generator (`--emit-xdp-c --port ...`) featuring Tor consensus IP allowlist maps (`XDP_PASS`), high-socket non-relay flooder drop maps (`XDP_DROP`), and O(1) per-CPU LRU `SYN` token buckets.
- Deterministic `1-in-16` overload stride sampling (`--max-exact-sockets`, default `50000`) in `/proc/net/tcp[6]` parsing with strict `>= 2` sample privacy floor so honest single-socket clients can never be revealed by stride scaling.
- 8-suite verification coverage including `DefenseStateMachine`, entropy classification, XDP C shield rendering, overload stride privacy invariants, and packaging parity (`setup.py` `py_modules`).

## [0.1.0] - 2026-11-13
### Added
- Standalone privacy-preserving Tor relay DoS triage CLI (`bin/relaysentry`, `src/relaysentry.py`) with UTC reporting timestamps and clean `--watch` `KeyboardInterrupt` exit.
- Ephemeral `os.urandom(32)` HMAC-SHA256 peer anonymizer with `--reveal-flooders` gated to `>= --flood-threshold` concurrent sockets (`src/privacy_vault.py`).
- Direct zero-subprocess Linux `/proc/net/tcp` and `/proc/net/tcp6` socket + RX/TX queue parser (`src/telemetry_procfs.py`).
- Bounded `MetricsPort` Prometheus exposition parser and `ControlPort` `GETINFO orconn-status` reader with SSRF redirect rejection and multi-instance shared-IP fingerprint correlation (`src/telemetry_tor.py`, `src/correlator.py`).
- Field-filtered `gzip` Onionoo consensus & `effective_family` / ASN indexer + native C Tor `dir-spec` v3 `cached-consensus` parser with bounded streaming decompression (CWE-409), pre-read file bounds (CWE-400), `mkstemp` `0600` atomic cache (1-hour TTL reuse, `--refresh`, `--no-cache`), strict HTTPS redirect policy, and neutral non-attributing HTTP `User-Agent` (`src/consensus_index.py`).
- 7-suite offline synthetic flood, cache TTL/`--refresh`/`gzip`, security boundary (CWE-409/CWE-400/SSRF), and loopback `MetricsPort`/`ControlPort` testbench (`test/verify_relaysentry.py`).
