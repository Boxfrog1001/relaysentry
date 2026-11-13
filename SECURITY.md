# Security Policy

## Scope & Privacy Posture
`RelaySentry` is a defensive relay-side DoS telemetry tool for Tor operators (`Guard`, `Middle`, `Exit`, and `HSDir` nodes). Because Tor relay socket tables can contain honest client IPs, preserving Tor user anonymity takes priority over every other feature.

## Enforced Security Hardening
- **No Shell Execution:** Kernel socket telemetry reads `/proc/net/tcp` and `/proc/net/tcp6` directly in pure Python (`shell=True` is forbidden codebase-wide).
- **Strict Ephemeral Anonymization:** Non-consensus peer IPs are HMAC-SHA256 tokenized using a volatile `os.urandom(32)` session key generated per process and never written to disk.
- **Flood-Threshold Reveal Gate:** `--reveal-flooders` reveals raw IPs strictly in terminal RAM and **only** for peers matching `>= --flood-threshold` concurrent sockets (default `25`).
- **Bounded Network & Control Parsing:** HTTP `MetricsPort` fetches enforce strict byte caps (`8 MiB`) and timeouts; `ControlPort` readers enforce strict line caps and bounded 32-byte cookie auth files.
- **Amnesic & Restricted Cache Mode:** Supports `--no-cache` RAM-only operation; file caches are created strictly with `0600` permissions and strict IP/fingerprint validation.

## Supported Versions
| Version | Status |
| :--- | :--- |
| `0.1.x` | Supported |

## Reporting a Vulnerability
If you find a privacy leak (such as non-relay IP disclosure below threshold), parser DoS (CWE-400/CWE-409), symlink race, or authentication flaw, please disclose it privately via the repository's GitHub Private Vulnerability Reporting (Security Advisories) tab before public posting.
