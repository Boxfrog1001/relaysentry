"""Zero-subprocess Linux procfs TCP telemetry reader for RelaySentry.

Parses /proc/net/tcp and /proc/net/tcp6 directly in pure Python, decoding
Linux kernel socket states and tx_queue/rx_queue byte depths for monitored
ORPort and DirPort endpoints without shelling out to external binaries.
"""

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}

DEFAULT_MAX_EXACT_SOCKETS = 50000
OVERLOAD_STRIDE = 16

HEX_IP_PORT_RE = re.compile(r"^([0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}):([0-9A-Fa-f]{4})$")
HEX_PAIR_RE = re.compile(r"^([0-9A-Fa-f]{8}):([0-9A-Fa-f]{8})$")


@dataclass(frozen=True)
class SocketEntry:
    """Normalized kernel socket entry for a monitored relay port."""

    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    tx_queue: int
    rx_queue: int
    uid: int


def decode_proc_addr(token: str) -> tuple[str, int] | None:
    """Decode Linux procfs little-endian hex IPv4/IPv6 + port token."""
    m = HEX_IP_PORT_RE.match(token)
    if not m:
        return None
    hex_ip, hex_port = m.groups()
    port = int(hex_port, 16)
    raw = bytes.fromhex(hex_ip)
    if len(raw) == 4:
        # /proc/net/tcp stores IPv4 as host-endian 32-bit u32 on x86/ARM Linux.
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.IPv4Address(raw[::-1])
    else:
        # /proc/net/tcp6 stores 4 consecutive 32-bit host-endian words.
        be_bytes = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
        v6 = ipaddress.IPv6Address(be_bytes)
        addr = v6.ipv4_mapped if v6.ipv4_mapped is not None else v6
    return addr.compressed, port


def _decode_socket_line(
    line: str,
    monitored_ports: set[int],
    include_listen: bool,
) -> SocketEntry | None:
    """Decode one /proc/net/tcp[6] line into SocketEntry if it matches monitored_ports."""
    parts = line.split()
    if len(parts) < 8 or parts[0] == "sl":
        return None
    local = decode_proc_addr(parts[1])
    remote = decode_proc_addr(parts[2])
    if local is None or remote is None:
        return None
    local_ip, local_port = local
    remote_ip, remote_port = remote
    if local_port not in monitored_ports:
        return None
    st_code = parts[3].upper()
    state = TCP_STATES.get(st_code, f"STATE_{st_code}")
    if not include_listen and state == "LISTEN":
        return None
    q_match = HEX_PAIR_RE.match(parts[4])
    tx_q = int(q_match.group(1), 16) if q_match else 0
    rx_q = int(q_match.group(2), 16) if q_match else 0
    try:
        uid = int(parts[7])
    except ValueError:
        uid = -1
    return SocketEntry(
        local_ip=local_ip,
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        state=state,
        tx_queue=tx_q,
        rx_queue=rx_q,
        uid=uid,
    )


def parse_proc_net_tcp_lines_bounded(
    lines: Iterable[str],
    monitored_ports: set[int],
    include_listen: bool = False,
    max_exact_sockets: int = DEFAULT_MAX_EXACT_SOCKETS,
    overload_stride: int = OVERLOAD_STRIDE,
) -> tuple[list[SocketEntry], int]:
    """Parse /proc/net/tcp* lines with automatic 1-in-N overload stride above max_exact_sockets."""
    entries: list[SocketEntry] = []
    stride = 1
    match_idx = 0
    cap = max_exact_sockets if max_exact_sockets > 0 else 0

    for line in lines:
        parts = line.split()
        if len(parts) < 8 or parts[0] == "sl":
            continue
        st_code = parts[3].upper()
        # Exclude LISTEN (0A) unless requested, and always exclude TIME_WAIT / closing states.
        if st_code == "0A":
            if not include_listen:
                continue
        elif st_code not in ("01", "02", "03"):
            continue
        try:
            _, port_hex = parts[1].rsplit(":", 1)
            local_port = int(port_hex, 16)
        except ValueError:
            continue
        if local_port not in monitored_ports:
            continue

        if cap and stride == 1 and match_idx >= cap:
            stride = max(2, overload_stride)
            entries = entries[::stride]

        if match_idx % stride == 0:
            local = decode_proc_addr(parts[1])
            remote = decode_proc_addr(parts[2])
            if local is not None and remote is not None:
                q_match = HEX_PAIR_RE.match(parts[4])
                tx_q = int(q_match.group(1), 16) if q_match else 0
                rx_q = int(q_match.group(2), 16) if q_match else 0
                try:
                    uid = int(parts[7])
                except ValueError:
                    uid = -1
                entries.append(
                    SocketEntry(
                        local_ip=local[0],
                        local_port=local[1],
                        remote_ip=remote[0],
                        remote_port=remote[1],
                        state=TCP_STATES.get(st_code, f"STATE_{st_code}"),
                        tx_queue=tx_q,
                        rx_queue=rx_q,
                        uid=uid,
                    )
                )
        match_idx += 1

    return entries, stride


def parse_proc_net_tcp_lines(
    lines: Iterable[str],
    monitored_ports: set[int],
    include_listen: bool = False,
) -> list[SocketEntry]:
    """Parse lines from /proc/net/tcp or /proc/net/tcp6 filtered to monitored local ports."""
    entries, _ = parse_proc_net_tcp_lines_bounded(
        lines,
        monitored_ports,
        include_listen=include_listen,
        max_exact_sockets=0,
    )
    return entries


def read_live_procfs_sockets_bounded(
    monitored_ports: set[int],
    tcp4_path: Path = Path("/proc/net/tcp"),
    tcp6_path: Path = Path("/proc/net/tcp6"),
    max_exact_sockets: int = DEFAULT_MAX_EXACT_SOCKETS,
) -> tuple[list[SocketEntry], int]:
    """Read and decode active TCPv4/TCPv6 sockets with overload stride & 64 MiB byte cap."""
    max_procfs_bytes = 64 * 1024 * 1024

    def _iter_files():
        total = 0
        for path in (tcp4_path, tcp6_path):
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    total += len(line.encode("utf-8", errors="replace"))
                    if total > max_procfs_bytes:
                        return
                    yield line

    return parse_proc_net_tcp_lines_bounded(
        _iter_files(),
        monitored_ports,
        max_exact_sockets=max_exact_sockets,
    )


def read_live_procfs_sockets(
    monitored_ports: set[int],
    tcp4_path: Path = Path("/proc/net/tcp"),
    tcp6_path: Path = Path("/proc/net/tcp6"),
) -> list[SocketEntry]:
    """Read and decode active TCPv4/TCPv6 sockets for monitored relay ports."""
    entries, _ = read_live_procfs_sockets_bounded(
        monitored_ports,
        tcp4_path=tcp4_path,
        tcp6_path=tcp6_path,
        max_exact_sockets=0,
    )
    return entries
