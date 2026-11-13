"""Tor Consensus / Onionoo fast IP & Fingerprint index for RelaySentry.

Indexes consensus relays by canonical IPv4/IPv6 address and uppercase
40-hex RSA fingerprint so live DoS telemetry can immediately separate public
Tor relays (including effective_family, ASN, flags, overload timestamps) from
non-relay client/bot IPs without touching honest client privacy.
"""

import base64
import ipaddress
import json
import os
import re
import stat
import tempfile
import time
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path

from privacy_vault import normalize_ip

ONIONOO_DETAILS_URL = "https://onionoo.torproject.org/details"
ONIONOO_FIELDS = (
    "nickname,fingerprint,running,or_addresses,dir_address,flags,"
    "as,as_name,effective_family,consensus_weight,version,overload_general_timestamp"
)
DEFAULT_CACHE_PATH = Path.home() / ".cache" / "relaysentry" / "onionoo_details.json"
DEFAULT_CACHE_TTL_SECONDS = 3600
MAX_CONSENSUS_BYTES = 128 * 1024 * 1024  # 128 MiB bounded read
FINGERPRINT_RE = re.compile(r"^\$?([0-9A-Fa-f]{40})(?:[=~].*)?$")
_DATE_TOKEN_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def clean_fingerprint(raw: str) -> str:
    """Normalize a Tor fingerprint token ($/<id>/~nick) to uppercase 40 hex chars."""
    m = FINGERPRINT_RE.match((raw or "").strip())
    return m.group(1).upper() if m else ""


@dataclass(frozen=True)
class RelayMeta:
    """Public consensus metadata for a known Tor relay."""

    fingerprint: str
    nickname: str
    flags: tuple[str, ...]
    as_number: str
    as_name: str
    effective_family: tuple[str, ...]
    consensus_weight: int
    version: str
    or_ips: tuple[str, ...]
    primary_ipv4_24: str
    overloaded: bool


class ConsensusIndex:
    """O(1) lookup index from canonical peer IP or fingerprint to RelayMeta."""

    def __init__(self, relays_by_fp: dict[str, RelayMeta], ip_to_fps: dict[str, list[str]]):
        self.relays_by_fp = relays_by_fp
        self.ip_to_fps = ip_to_fps

    @classmethod
    def from_onionoo_payload(cls, payload: dict) -> "ConsensusIndex":
        """Build O(1) lookup tables from Onionoo /details JSON payload."""
        relays_by_fp: dict[str, RelayMeta] = {}
        ip_to_fps: dict[str, list[str]] = {}

        for raw in payload.get("relays", []):
            if raw.get("running") is False:
                continue
            fp = clean_fingerprint(raw.get("fingerprint", ""))
            if not fp:
                continue

            or_ips_list: list[str] = []
            ipv4_24 = ""
            raw_addrs = list(raw.get("or_addresses") or [])
            if raw.get("dir_address"):
                raw_addrs.append(raw["dir_address"])
            for entry in raw_addrs:
                try:
                    cip = normalize_ip(str(entry))
                except ValueError:
                    continue
                if cip not in or_ips_list:
                    or_ips_list.append(cip)
                addr_obj = ipaddress.ip_address(cip)
                if isinstance(addr_obj, ipaddress.IPv4Address) and not ipv4_24:
                    ipv4_24 = str(ipaddress.IPv4Network(f"{cip}/24", strict=False))

            fam = tuple(
                sorted(
                    {
                        clean_fingerprint(x)
                        for x in (raw.get("effective_family") or [])
                        if clean_fingerprint(x) and clean_fingerprint(x) != fp
                    }
                )
            )
            meta = RelayMeta(
                fingerprint=fp,
                nickname=str(raw.get("nickname") or "Unnamed")[:32],
                flags=tuple(str(f) for f in (raw.get("flags") or [])),
                as_number=str(raw.get("as") or "AS_UNKNOWN"),
                as_name=str(raw.get("as_name") or "Unknown ASN")[:64],
                effective_family=fam,
                consensus_weight=int(raw.get("consensus_weight") or 0),
                version=str(raw.get("version") or "unknown")[:24],
                or_ips=tuple(or_ips_list),
                primary_ipv4_24=ipv4_24 or "ipv6_or_unknown",
                overloaded=bool(raw.get("overload_general_timestamp")),
            )
            relays_by_fp[fp] = meta
            for cip in or_ips_list:
                ip_to_fps.setdefault(cip, []).append(fp)

        return cls(relays_by_fp=relays_by_fp, ip_to_fps=ip_to_fps)

    @classmethod
    def from_cached_consensus(cls, text: str) -> "ConsensusIndex":
        """Build O(1) index directly from Tor v3 network-status cached-consensus."""
        relays_by_fp: dict[str, RelayMeta] = {}
        ip_to_fps: dict[str, list[str]] = {}
        current: dict | None = None

        def _flush() -> None:
            if not current:
                return
            fp = current["fp"]
            or_ips: list[str] = current["ips"]
            ipv4_24 = ""
            for cip in or_ips:
                addr_obj = ipaddress.ip_address(cip)
                if isinstance(addr_obj, ipaddress.IPv4Address):
                    ipv4_24 = str(ipaddress.IPv4Network(f"{cip}/24", strict=False))
                    break
            meta = RelayMeta(
                fingerprint=fp,
                nickname=current["nick"],
                flags=tuple(current["flags"]),
                as_number="AS_LOCAL",
                as_name="Consensus Cache (no AS lookup)",
                effective_family=(),
                consensus_weight=current["weight"],
                version=current["version"],
                or_ips=tuple(or_ips),
                primary_ipv4_24=ipv4_24 or "ipv6_or_unknown",
                overloaded=False,
            )
            relays_by_fp[fp] = meta
            for cip in or_ips:
                ip_to_fps.setdefault(cip, []).append(fp)

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("r "):
                _flush()
                parts = line.split()
                if len(parts) < 8:
                    current = None
                    continue
                # v3 full consensus includes descriptor digest (`parts[3]`, date at `parts[4]`, IP at `parts[6]`);
                # microdesc consensus omits digest (date at `parts[3]`, IP at `parts[5]`).
                if _DATE_TOKEN_RE.match(parts[3]):
                    ip_raw = parts[5]
                elif len(parts) >= 9 and _DATE_TOKEN_RE.match(parts[4]):
                    ip_raw = parts[6]
                elif len(parts) == 8:
                    ip_raw = parts[5]
                else:
                    ip_raw = parts[6]
                nick, b64_id = parts[1], parts[2]
                pad = "=" * ((4 - len(b64_id) % 4) % 4)
                try:
                    fp = base64.b64decode(b64_id + pad).hex().upper()
                    cip = normalize_ip(ip_raw)
                except Exception:
                    current = None
                    continue
                if len(fp) != 40:
                    current = None
                    continue
                current = {
                    "fp": fp,
                    "nick": nick[:32],
                    "ips": [cip],
                    "flags": [],
                    "weight": 0,
                    "version": "unknown",
                }
            elif current is not None:
                if line.startswith("a "):
                    try:
                        aip = normalize_ip(line[2:].strip())
                        if aip not in current["ips"]:
                            current["ips"].append(aip)
                    except ValueError:
                        pass
                elif line.startswith("s "):
                    current["flags"] = line.split()[1:]
                elif line.startswith("v "):
                    current["version"] = line[2:].strip()[:24]
                elif line.startswith("w "):
                    for tok in line.split()[1:]:
                        if tok.startswith("Bandwidth="):
                            try:
                                current["weight"] = int(tok.split("=", 1)[1])
                            except ValueError:
                                pass
        _flush()
        return cls(relays_by_fp=relays_by_fp, ip_to_fps=ip_to_fps)

    def lookup_ip(self, ip_str: str) -> list[RelayMeta]:
        """Return matching running consensus relays for canonical peer IP."""
        try:
            cip = normalize_ip(ip_str)
        except ValueError:
            return []
        fps = self.ip_to_fps.get(cip, [])
        return [self.relays_by_fp[fp] for fp in fps if fp in self.relays_by_fp]

    def lookup_fp(self, fp_str: str) -> RelayMeta | None:
        """Return matching consensus relay by 40-hex fingerprint."""
        fp = clean_fingerprint(fp_str)
        return self.relays_by_fp.get(fp)


def _write_secure_cache(path: Path, raw_bytes: bytes) -> None:
    """Write consensus cache atomically with strict 0600 permissions (no world read)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, tmp_str = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_str)
    try:
        view = memoryview(raw_bytes)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.close(fd)
        fd = -1
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except Exception:
        if fd != -1:
            os.close(fd)
        tmp_path.unlink(missing_ok=True)
        raise


def _read_bounded_file(path: Path, max_bytes: int, label: str) -> bytes:
    """Read local file safely within strict size bounds (CWE-400)."""
    with path.open("rb") as fh:
        st = os.fstat(fh.fileno())
        if stat.S_ISREG(st.st_mode) and st.st_size > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes // (1024 * 1024) or 1} MiB safety bound")
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes // (1024 * 1024) or 1} MiB safety bound")
    return data


def _decompress_gzip_bounded(raw_bytes: bytes, max_bytes: int, label: str) -> bytes:
    """Decompress gzip payload while enforcing output cap against CWE-409 bombs."""
    chunks: list[bytes] = []
    total_out = 0
    buf = raw_bytes
    while buf:
        decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
        offset = 0
        while offset < len(buf) and not decomp.eof:
            data = buf[offset : offset + 65536]
            offset += len(data)
            while data and not decomp.eof:
                remaining = max_bytes - total_out
                out = decomp.decompress(data, remaining + 1)
                total_out += len(out)
                if total_out > max_bytes:
                    raise ValueError(f"{label} exceeded decompressed safety bound ({max_bytes} bytes)")
                chunks.append(out)
                data = decomp.unconsumed_tail
        if not decomp.eof:
            raise EOFError("Compressed gzip stream ended unexpectedly")
        buf = decomp.unused_data + buf[offset:]
    return b"".join(chunks)


class _StrictOnionooRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow only HTTPS redirects to official *.torproject.org Onionoo hosts."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not (
            host == "torproject.org" or host.endswith(".torproject.org")
        ):
            raise ValueError(f"Blocked unsafe Onionoo HTTP redirect target: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def load_consensus_index(
    consensus_file: Path | None = None,
    no_cache: bool = False,
    offline: bool = False,
    proxy_url: str | None = None,
    cache_path: Path = DEFAULT_CACHE_PATH,
    cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
    refresh: bool = False,
    timeout: int = 60,
) -> ConsensusIndex:
    """Load Tor consensus from explicit file, hardened local cache, or Onionoo."""
    if consensus_file is not None:
        raw_bytes = _read_bounded_file(consensus_file, MAX_CONSENSUS_BYTES, "Consensus file")
        decoded = raw_bytes.decode("utf-8", errors="replace")
        if decoded.lstrip().startswith("network-status-version"):
            return ConsensusIndex.from_cached_consensus(decoded)
        return ConsensusIndex.from_onionoo_payload(json.loads(decoded))

    if not no_cache and cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if offline or (not refresh and age < cache_ttl_seconds):
            try:
                raw_bytes = _read_bounded_file(cache_path, MAX_CONSENSUS_BYTES, "Cached consensus file")
                return ConsensusIndex.from_onionoo_payload(json.loads(raw_bytes.decode("utf-8")))
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                if offline:
                    raise

    if offline:
        return ConsensusIndex({}, {})

    handlers: list[urllib.request.BaseHandler] = [_StrictOnionooRedirectHandler()]
    if proxy_url:
        parsed = urllib.parse.urlparse(proxy_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only http:// or https:// URLs allowed for --proxy")
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(
        f"{ONIONOO_DETAILS_URL}?running=true&fields={ONIONOO_FIELDS}",
        headers={
            "User-Agent": "RelaySentry/0.3",
            "Accept-Encoding": "gzip",
        },
    )
    with opener.open(req, timeout=timeout) as resp:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_CONSENSUS_BYTES:
                raise ValueError("Onionoo payload exceeded 128 MiB bound")
            chunks.append(chunk)
        raw_bytes = b"".join(chunks)
        if resp.headers.get("Content-Encoding", "").lower() == "gzip":
            raw_bytes = _decompress_gzip_bounded(raw_bytes, MAX_CONSENSUS_BYTES, "Onionoo payload")

    if not no_cache:
        _write_secure_cache(cache_path, raw_bytes)
    return ConsensusIndex.from_onionoo_payload(json.loads(raw_bytes.decode("utf-8")))
