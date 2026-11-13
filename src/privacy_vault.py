"""Ephemeral CSPRNG peer privacy vault for RelaySentry.

Guarantees that non-consensus (potential honest Tor client) IP addresses
never touch disk and are masked with a volatile per-session HMAC-SHA256
key by default. Even when an operator enables --reveal-flooders during an
active attack, peers below the flood_threshold remain anonymized.
"""

import hashlib
import hmac
import ipaddress
import os
from dataclasses import dataclass


def normalize_ip(raw_ip: str) -> str:
    """Canonicalize IPv4/IPv6 strings (stripping ports, brackets, IPv4-mapped prefix)."""
    text = (raw_ip or "").strip()
    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            text = text[1:end]
    elif text.count(":") == 1:
        host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            text = host
    addr = ipaddress.ip_address(text)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.compressed


@dataclass(frozen=True)
class PeerLabel:
    """Privacy-safe display descriptor for a non-consensus peer."""

    token: str
    disclosed_ip: str | None
    masked: bool


class EphemeralPrivacyVault:
    """Session-scoped HMAC-SHA256 anonymizer for non-consensus peers."""

    def __init__(self, reveal_flooders: bool = False, flood_threshold: int = 25):
        if flood_threshold < 2:
            raise ValueError("flood_threshold must be >= 2 to prevent single-client disclosure")
        # Volatile 256-bit key lives solely in RAM for this run.
        self._session_key = os.urandom(32)
        self._reveal_flooders = bool(reveal_flooders)
        self._flood_threshold = int(flood_threshold)

    def anonymize_ip(self, canonical_ip: str) -> str:
        """Return deterministic-within-session anon#<16-hex> token."""
        addr_bytes = ipaddress.ip_address(canonical_ip).packed
        digest = hmac.new(self._session_key, addr_bytes, hashlib.sha256).hexdigest()
        return f"anon#{digest[:16]}"

    def classify_nonrelay(self, raw_ip: str, concurrent_sockets: int) -> PeerLabel:
        """Mask non-relay peers unless reveal_flooders is set AND sockets >= threshold."""
        canonical = normalize_ip(raw_ip)
        token = self.anonymize_ip(canonical)
        if self._reveal_flooders and concurrent_sockets >= self._flood_threshold:
            return PeerLabel(token=token, disclosed_ip=canonical, masked=False)
        return PeerLabel(token=token, disclosed_ip=None, masked=True)
