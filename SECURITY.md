# Security Policy

## Scope & Privacy Posture
`RelaySentry` is a defensive relay-side DoS telemetry tool for Tor operators (`Guard`, `Middle`, `Exit`, and `HSDir` nodes). Because Tor relay socket tables can contain honest client IPs, preserving Tor user anonymity takes priority over every other feature.

## Enforced Security Hardening
- **No Shell Execution:** Kernel socket telemetry reads `/proc/net/tcp` and `/proc/net/tcp6` directly in pure Python (`shell=True` is forbidden codebase-wide). Optional active firewall enforcement (`--enforce-shield`, `--shield-dry-run`) invokes `/usr/sbin/nft` or `/usr/sbin/bpftool` strictly via parameterized argument arrays and stdin (`subprocess.run(..., shell=False)`).
- **Strict Ephemeral Anonymization:** Non-consensus peer IPs are HMAC-SHA256 tokenized using a volatile `os.urandom(32)` session key generated per process and never written to disk (including `added_bans` shield summaries unless `--reveal-flooders` is explicitly set).
- **Flood-Threshold Reveal Gate & Non-Blocking Shield Safety:** `--reveal-flooders` reveals raw IPs strictly in terminal RAM and **only** for peers matching `>= --flood-threshold` concurrent sockets (default `25`). Under `--enforce-shield`, Consensus relays, loopback addresses, and operator `--allow-cidr` ranges are exempted from kernel block sets, and temporary bans expire automatically (`--ban-ttl` / `NORMAL` recovery).
- **Bounded Network & Control Parsing:** HTTP `MetricsPort` fetches enforce strict byte caps (`8 MiB`), float-overflow guards, and timeouts (`--metrics-timeout`); `ControlPort` readers enforce strict line caps and bounded 32-byte cookie auth files; live `/proc/net/tcp[6]` and cached consensus parsing enforce strict byte/decompression bounds (CWE-400 / CWE-409).
- **Amnesic & Restricted Cache Mode:** Supports `--no-cache` RAM-only operation; file caches are created strictly with `0600` permissions via `mkstemp` + atomic rename (`chmod 0600` on existing parent directories `0700`) and strict IP/fingerprint validation. Note: `--enforce-shield` cannot operate with `--offline` against an empty consensus cache.

## Supported Versions
| Version | Status |
| :--- | :--- |
| `0.3.x` | Experimental Beta (Frozen Scope) |
| `0.1.x`–`0.2.x` | Unmaintained |

## Reporting a Vulnerability
If you find a privacy leak (such as non-relay IP disclosure below threshold), parser DoS (CWE-400/CWE-409), symlink race, or authentication flaw, please disclose it privately via the repository's GitHub Private Vulnerability Reporting (Security Advisories) tab before public posting.
