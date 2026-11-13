"""Bounded Tor MetricsPort & ControlPort telemetry reader for RelaySentry.

Parses official Prometheus MetricsPort exposition lines (tor_relay_connections,
tor_relay_load_onionskins_total, tor_relay_load_oom_bytes_total,
tor_relay_load_socket_total, tor_relay_load_tcp_exhaustion*) and optional local
ControlPort `GETINFO orconn-status` entries with strict byte/line caps.
"""

import re
import socket
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

MAX_METRICS_BYTES = 8 * 1024 * 1024  # 8 MiB hard cap against HTTP memory DoS
MAX_CONTROL_LINES = 50000
MAX_CONTROL_BYTES = 4 * 1024 * 1024

METRIC_LINE_RE = re.compile(
    r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)\s*$"
)
LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')
ORCONN_RE = re.compile(r"^\$([0-9A-Fa-f]{40})(?:[=~]([A-Za-z0-9_.-]+))?\s+([A-Z_]+)")
CONTROL_END_RE = re.compile(r"^(?:250 |5\d{2} )")


def _parse_labels(raw: str) -> dict[str, str]:
    """Parse Prometheus metric label key="val" pairs safely."""
    if not raw:
        return {}
    return {k: v.replace('\\"', '"') for k, v in LABEL_RE.findall(raw)}


@dataclass
class TorMetricsSnapshot:
    """Structured snapshot of relevant Tor MetricsPort relay load counters."""

    connections_opened: int = 0
    or_connections_opened: int = 0
    dir_connections_opened: int = 0
    ntor_processed: int = 0
    ntor_dropped: int = 0
    ntor_v3_processed: int = 0
    ntor_v3_dropped: int = 0
    oom_bytes_total: int = 0
    socket_total: int = 0
    tcp_exhaustion_total: int = 0
    global_rate_limit_total: int = 0
    begindir_rate_rejected: int = 0
    begindir_rejected: int = 0
    begindir_hsdir_rejected: int = 0
    circuit_rejected: int = 0
    circuit_killed_max_cell: int = 0
    conn_rejected: int = 0
    begindir_streams_total: int = 0
    dos_by_type: dict[str, int] = field(default_factory=dict)
    extra_load_counters: dict[str, float] = field(default_factory=dict)

    @property
    def total_begindir_rejected(self) -> int:
        return self.begindir_rate_rejected + self.begindir_rejected + self.begindir_hsdir_rejected

    @property
    def total_onionskins_dropped(self) -> int:
        return self.ntor_dropped + self.ntor_v3_dropped

    @property
    def total_onionskins_processed(self) -> int:
        return self.ntor_processed + self.ntor_v3_processed

    @property
    def drop_ratio_pct(self) -> float:
        denom = self.total_onionskins_processed + self.total_onionskins_dropped
        if denom <= 0:
            return 0.0
        return (self.total_onionskins_dropped / denom) * 100.0


_DOS_TYPE_FIELD_MAP = {
    "begindir_rate_rejected": "begindir_rate_rejected",
    "begindir_rejected": "begindir_rejected",
    "begindir_hsdir_rejected": "begindir_hsdir_rejected",
    "circuit_rejected": "circuit_rejected",
    "circuit_killed_max_cell": "circuit_killed_max_cell",
    "circuit_killed_max_cell_outq": "circuit_killed_max_cell",
    "conn_rejected": "conn_rejected",
    "concurrent_conn_rejected": "conn_rejected",
}


def parse_prometheus_metrics(text: str) -> TorMetricsSnapshot:
    """Parse Tor Prometheus MetricsPort text safely into TorMetricsSnapshot."""
    snap = TorMetricsSnapshot()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = METRIC_LINE_RE.match(line)
        if not m:
            continue
        name, raw_labels, raw_val = m.groups()
        val = float(raw_val)
        labels = _parse_labels(raw_labels)

        if name in ("tor_relay_connections", "tor_relay_connections_total"):
            if labels.get("state") == "opened":
                conn_type = labels.get("type", "").lower()
                if "listener" in conn_type:
                    continue
                snap.connections_opened += int(val)
                if conn_type == "directory":
                    snap.dir_connections_opened += int(val)
                elif conn_type == "or":
                    snap.or_connections_opened += int(val)
        elif name == "tor_relay_load_onionskins_total":
            otype = labels.get("type", "")
            action = labels.get("action", "")
            if otype == "ntor" and action == "processed":
                snap.ntor_processed += int(val)
            elif otype == "ntor" and action == "dropped":
                snap.ntor_dropped += int(val)
            elif otype == "ntor_v3" and action == "processed":
                snap.ntor_v3_processed += int(val)
            elif otype == "ntor_v3" and action == "dropped":
                snap.ntor_v3_dropped += int(val)
        elif name in ("tor_relay_load_oom_bytes_total", "tor_relay_load_oom_bytes"):
            snap.oom_bytes_total += int(val)
        elif name == "tor_relay_load_socket_total":
            if labels.get("state") == "opened":
                snap.socket_total += int(val)
        elif name in ("tor_relay_load_tcp_exhaustion_total", "tor_relay_load_tcp_exhaustion"):
            snap.tcp_exhaustion_total += int(val)
        elif name in ("tor_relay_load_global_rate_limit_reached_total",):
            snap.global_rate_limit_total += int(val)
        elif name == "tor_relay_dos_total":
            dtype = labels.get("type", "unknown")
            count = int(val)
            snap.dos_by_type[dtype] = snap.dos_by_type.get(dtype, 0) + count
            attr = _DOS_TYPE_FIELD_MAP.get(dtype)
            if attr:
                setattr(snap, attr, getattr(snap, attr) + count)
        elif name == "tor_relay_streams_total":
            cmd = (labels.get("cmd") or labels.get("type") or "").upper()
            if cmd == "BEGIN_DIR":
                snap.begindir_streams_total += int(val)
        elif name.startswith("tor_relay_load_") or name.startswith("tor_relay_dos_"):
            snap.extra_load_counters[name] = snap.extra_load_counters.get(name, 0.0) + val

    return snap


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject HTTP redirects on local/tunneled MetricsPort scrapes (SSRF hardening)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError(f"Blocked unexpected HTTP redirect from MetricsPort: {newurl}")


def fetch_metrics_port(url: str, timeout: float = 5.0) -> TorMetricsSnapshot:
    """Fetch local/tunnel Tor MetricsPort HTTP endpoint with strict read cap."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("MetricsPort URL must use http:// or https://")
    opener = urllib.request.build_opener(_NoRedirectHandler())
    req = urllib.request.Request(url, headers={"User-Agent": "RelaySentry/0.3"})
    with opener.open(req, timeout=timeout) as resp:
        buf = resp.read(MAX_METRICS_BYTES + 1)
        if len(buf) > MAX_METRICS_BYTES:
            raise ValueError("MetricsPort response exceeded 8 MiB safety cap")
    return parse_prometheus_metrics(buf.decode("utf-8", errors="replace"))


@dataclass(frozen=True)
class OrConnEntry:
    """Parsed Tor ControlPort GETINFO orconn-status record."""

    fingerprint: str
    nickname: str
    status: str


def parse_orconn_lines(lines: list[str]) -> list[OrConnEntry]:
    """Parse Tor control-spec `orconn-status` lines (`$FP[=Nick] STATUS`)."""
    entries: list[OrConnEntry] = []
    for raw in lines:
        m = ORCONN_RE.match(raw.strip())
        if not m:
            continue
        fp, nick, status = m.groups()
        entries.append(
            OrConnEntry(
                fingerprint=fp.upper(),
                nickname=nick or "Unnamed",
                status=status,
            )
        )
    return entries


def _recv_control_block(sock: socket.socket) -> list[str]:
    """Read lines from ControlPort up to `250 OK` within strict byte/line caps."""
    lines: list[str] = []
    total_bytes = 0
    buf = b""
    while len(lines) < MAX_CONTROL_LINES:
        chunk = sock.recv(4096)
        if not chunk:
            break
        total_bytes += len(chunk)
        if total_bytes > MAX_CONTROL_BYTES:
            raise ValueError("ControlPort reply exceeded 4 MiB safety cap")
        buf += chunk
        while b"\n" in buf:
            raw_line, buf = buf.split(b"\n", 1)
            line = raw_line.rstrip(b"\r").decode("utf-8", errors="replace")
            lines.append(line)
            if CONTROL_END_RE.match(line):
                return lines
    return lines


def query_control_orconn(
    host: str = "127.0.0.1",
    port: int = 9051,
    cookie_path: Path | None = None,
    password: str | None = None,
    timeout: float = 5.0,
) -> list[OrConnEntry]:
    """Query local Tor ControlPort for `GETINFO orconn-status` safely."""
    if not (1 <= port <= 65535):
        raise ValueError(f"Invalid ControlPort: {port}")
    auth_cmd = "AUTHENTICATE\r\n"
    if cookie_path is not None:
        with cookie_path.open("rb") as fh:
            raw_cookie = fh.read(33)
        if len(raw_cookie) != 32:
            raise ValueError("Tor ControlPort cookie must be exactly 32 bytes")
        auth_cmd = f"AUTHENTICATE {raw_cookie.hex()}\r\n"
    elif password is not None:
        safe_pw = password.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", "")
        auth_cmd = f'AUTHENTICATE "{safe_pw}"\r\n'

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(auth_cmd.encode("utf-8"))
        auth_resp = _recv_control_block(sock)
        if not auth_resp or not auth_resp[-1].startswith("250"):
            raise PermissionError(f"ControlPort AUTHENTICATE failed: {auth_resp[-1] if auth_resp else 'EOF'}")

        sock.sendall(b"GETINFO orconn-status\r\n")
        resp_lines = _recv_control_block(sock)
        sock.sendall(b"QUIT\r\n")

    return parse_orconn_lines(resp_lines)
