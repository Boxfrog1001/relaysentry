#!/usr/bin/env python3
"""Realistic 4-stage local sandbox simulator reproducing live Tor relay DoS vectors.

Replays local procfs /proc/net/tcp + /proc/net/tcp6 queues, Prometheus MetricsPort,
ControlPort ORCONN status, and Onionoo consensus fixtures entirely on loopback without
requiring a running Tor daemon or external dependencies:

  Stage 1: Healthy relay baseline (masked honest client, zero drops)
  Stage 2: Classic BEGIN_DIR "Thunderstorm" (DoSBeginDir* counters + HSDir/family surge)
  Stage 3: Post-0.4.9.16 half-open BEGIN_DIR stall bypass + stalled MetricsPort/ControlPort
  Stage 4: Distributed non-relay SYN/socket flood + kernel sk_buff bloat + recovery check
"""

from __future__ import annotations

import argparse
import http.server
import ipaddress
import json
import socket
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from consensus_index import load_consensus_index
from privacy_vault import EphemeralPrivacyVault
from relaysentry import _report_to_dict, format_terminal_report, run_once
from shield_engine import (
    DefenseStateMachine,
    ShieldController,
    TelemetryRingBuffer,
    generate_nft_consensus_sync,
    render_xdp_shield_c,
)


def _encode_ipv4_le(ip_str: str) -> str:
    return ipaddress.IPv4Address(ip_str).packed[::-1].hex().upper()


def _encode_ipv6_le_words(ip_str: str) -> str:
    raw = ipaddress.IPv6Address(ip_str).packed
    return b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4)).hex().upper()


def _proc_v4_line(
    idx: int,
    local_ip: str,
    local_port: int,
    remote_ip: str,
    remote_port: int,
    state_hex: str,
    tx_q: int = 0,
    rx_q: int = 0,
) -> str:
    return (
        f" {idx:3d}: {_encode_ipv4_le(local_ip)}:{local_port:04X} "
        f"{_encode_ipv4_le(remote_ip)}:{remote_port:04X} {state_hex} "
        f"{tx_q:08X}:{rx_q:08X} 00:00000000 00000000 105 0 {1000 + idx}"
    )


def _proc_v6_line(
    idx: int,
    local_ip: str,
    local_port: int,
    remote_ip: str,
    remote_port: int,
    state_hex: str,
    tx_q: int = 0,
    rx_q: int = 0,
) -> str:
    return (
        f" {idx:3d}: {_encode_ipv6_le_words(local_ip)}:{local_port:04X} "
        f"{_encode_ipv6_le_words(remote_ip)}:{remote_port:04X} {state_hex} "
        f"{tx_q:08X}:{rx_q:08X} 00:00000000 00000000 105 0 {2000 + idx}"
    )


def _write_consensus_fixture(path: Path) -> None:
    payload = {
        "relays": [
            {
                "nickname": "DirAuth01",
                "fingerprint": "A" * 40,
                "or_addresses": ["192.0.2.10:9001"],
                "flags": ["Authority", "Fast", "Running", "Stable", "V2Dir", "Valid"],
                "as": "AS64510",
                "as_name": "AuthorityNet",
                "effective_family": ["$" + "A" * 40],
                "overload_general_timestamp": 0,
            },
            {
                "nickname": "GuardHSDirA1",
                "fingerprint": "B" * 40,
                "or_addresses": ["198.51.100.11:9001"],
                "flags": ["Fast", "Guard", "HSDir", "Running", "Stable", "Valid"],
                "as": "AS64511",
                "as_name": "RelayFamilyNet",
                "effective_family": ["$" + "B" * 40, "$" + "C" * 40],
                "overload_general_timestamp": 1760000000,
            },
            {
                "nickname": "GuardHSDirA2",
                "fingerprint": "C" * 40,
                "or_addresses": ["198.51.100.12:9001"],
                "flags": ["Fast", "Guard", "HSDir", "Running", "Stable", "Valid"],
                "as": "AS64511",
                "as_name": "RelayFamilyNet",
                "effective_family": ["$" + "B" * 40, "$" + "C" * 40],
                "overload_general_timestamp": 0,
            },
            {
                "nickname": "GuardHSDirB1",
                "fingerprint": "D" * 40,
                "or_addresses": ["[2001:db8:1::13]:9001"],
                "flags": ["Fast", "HSDir", "Running", "Valid"],
                "as": "AS64512",
                "as_name": "DualStackNet",
                "effective_family": ["$" + "D" * 40],
                "overload_general_timestamp": 0,
            },
        ]
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


class _MockRelayTelemetry:
    """Thread-safe local MetricsPort HTTP + ControlPort TCP server supporting stall fault injection."""

    def __init__(self, cookie_bytes: bytes) -> None:
        self.cookie_bytes = cookie_bytes
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.stall_metrics = False
        self.stall_control = False
        self.stall_delay = 0.65
        self.metrics_body = ""
        self.orconn_lines: list[str] = []

        parent = self

        class MetricsHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                with parent.lock:
                    should_stall = parent.stall_metrics
                    body = parent.metrics_body
                    delay = parent.stall_delay
                if should_stall:
                    parent.stop_event.wait(timeout=delay)
                    return
                encoded = body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *args) -> None:
                return

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MetricsHandler)
        self.metrics_port = self.httpd.server_address[1]
        self._http_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

        self._ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._ctrl_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._ctrl_sock.bind(("127.0.0.1", 0))
        self._ctrl_sock.listen(16)
        self._ctrl_sock.settimeout(0.1)
        self.control_port = self._ctrl_sock.getsockname()[1]
        self._ctrl_thread = threading.Thread(target=self._serve_control, daemon=True)

    def start(self) -> None:
        self._http_thread.start()
        self._ctrl_thread.start()

    def close(self) -> None:
        self.stop_event.set()
        self.httpd.shutdown()
        self.httpd.server_close()
        self._ctrl_sock.close()
        self._ctrl_thread.join(timeout=1.5)

    def _handle_control_client(self, conn: socket.socket) -> None:
        expected_hex = self.cookie_bytes.hex().lower()
        with conn:
            conn.settimeout(1.0)
            try:
                data = conn.recv(4096).decode("utf-8", errors="replace")
            except OSError:
                return
            with self.lock:
                should_stall = self.stall_control
                lines = list(self.orconn_lines)
                delay = self.stall_delay
            if should_stall:
                self.stop_event.wait(timeout=delay)
                return
            if f"authenticate {expected_hex}" not in data.lower():
                conn.sendall(b"515 Bad authentication\r\n")
                return
            conn.sendall(b"250 OK\r\n")
            try:
                cmd = conn.recv(4096).decode("utf-8", errors="replace")
            except OSError:
                return
            if "GETINFO orconn-status" in cmd:
                reply = "250+orconn-status=\r\n" + "".join(f"{ln}\r\n" for ln in lines) + ".\r\n250 OK\r\n"
                conn.sendall(reply.encode("utf-8"))

    def _serve_control(self) -> None:
        while not self.stop_event.is_set():
            try:
                conn, _ = self._ctrl_sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_control_client, args=(conn,), daemon=True).start()


def _render_prometheus(
    *,
    conn_or: int,
    conn_dir: int,
    sock_tot: int,
    ntor_proc: int,
    ntor_drop: int,
    oom_bytes: int,
    begindir_rate_rej: int,
    begindir_rej: int,
    begindir_hsdir_rej: int,
    circuit_killed: int,
    conn_rej: int,
    begindir_streams: int,
) -> str:
    return "\n".join(
        [
            "# Prometheus simulation snapshot",
            f'tor_relay_connections_total{{type="OR",state="opened"}} {conn_or}',
            f'tor_relay_connections_total{{type="Directory",state="opened"}} {conn_dir}',
            f'tor_relay_load_socket_total{{state="opened"}} {sock_tot}',
            f'tor_relay_load_onionskins_total{{type="ntor",action="processed"}} {ntor_proc}',
            f'tor_relay_load_onionskins_total{{type="ntor",action="dropped"}} {ntor_drop}',
            f"tor_relay_load_oom_bytes_total {oom_bytes}",
            "tor_relay_load_tcp_exhaustion_total 0",
            "tor_relay_load_global_rate_limit_reached_total 0",
            f'tor_relay_dos_total{{type="begindir_rate_rejected"}} {begindir_rate_rej}',
            f'tor_relay_dos_total{{type="begindir_rejected"}} {begindir_rej}',
            f'tor_relay_dos_total{{type="begindir_hsdir_rejected"}} {begindir_hsdir_rej}',
            f'tor_relay_dos_total{{type="circuit_killed_max_cell"}} {circuit_killed}',
            f'tor_relay_dos_total{{type="conn_rejected"}} {conn_rej}',
            f'tor_relay_streams_total{{cmd="BEGIN_DIR"}} {begindir_streams}',
        ]
    )


def _write_proc_stage(
    tcp4_path: Path,
    tcp6_path: Path,
    stage: str,
) -> None:
    hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
    v4_lines = [hdr, _proc_v4_line(0, "0.0.0.0", 9001, "0.0.0.0", 0, "0A")]
    v6_lines = [hdr, _proc_v6_line(0, "::", 9001, "::", 0, "0A")]
    idx = 1

    # Always keep one honest 2-socket Tor client present to verify strict anonymity preservation.
    honest_client_ip = "203.0.113.40"
    for p_off in range(2):
        v4_lines.append(_proc_v4_line(idx, "192.0.2.5", 9001, honest_client_ip, 38000 + p_off, "01"))
        idx += 1

    if stage == "baseline":
        for peer_ip in ("192.0.2.10", "198.51.100.11", "198.51.100.12"):
            for k in range(3):
                v4_lines.append(_proc_v4_line(idx, "192.0.2.5", 9001, peer_ip, 41000 + k, "01"))
                idx += 1
        v6_lines.append(_proc_v6_line(idx, "2001:db8::5", 9001, "2001:db8:1::13", 41500, "01"))

    elif stage == "thunderstorm_classic":
        # Heavy consensus family circuit/BEGIN_DIR pressure on ORPort 9001 + DirPort 9030
        for k in range(42):
            v4_lines.append(
                _proc_v4_line(idx, "192.0.2.5", 9001, "198.51.100.11", 42000 + k, "01", tx_q=0x1000, rx_q=0x2000)
            )
            idx += 1
        for k in range(32):
            v4_lines.append(
                _proc_v4_line(idx, "192.0.2.5", 9030, "198.51.100.12", 43000 + k, "01", tx_q=0x0800, rx_q=0x2000)
            )
            idx += 1
        for k in range(8):
            v6_lines.append(
                _proc_v6_line(idx, "2001:db8::5", 9001, "2001:db8:1::13", 43500 + k, "01", tx_q=0x0800, rx_q=0x1000)
            )
            idx += 1

    elif stage == "half_open_bypass":
        # Post-0.4.9.16 half-open BEGIN_DIR stall: MetricsPort/ControlPort freeze while kernel queues balloon.
        for k in range(35):
            v4_lines.append(
                _proc_v4_line(idx, "192.0.2.5", 9001, "198.51.100.11", 44000 + k, "01", tx_q=0x4000, rx_q=0x8000)
            )
            idx += 1
        for k in range(28):
            v6_lines.append(
                _proc_v6_line(idx, "2001:db8::5", 9001, "2001:db8:1::13", 45000 + k, "01", tx_q=0x2000, rx_q=0x6000)
            )
            idx += 1

    elif stage == "distributed_nonrelay":
        # Distributed botnet non-relay SYN/socket flood across 64 distinct peers + 1 heavy v6 attacker
        for bot in range(64):
            bot_ip = f"203.0.113.{100 + bot}"
            for k in range(3):
                state = "03" if k < 2 else "01"
                v4_lines.append(
                    _proc_v4_line(idx, "192.0.2.5", 9001, bot_ip, 46000 + k, state, tx_q=0x0800, rx_q=0x2800)
                )
                idx += 1
        for k in range(36):
            v6_lines.append(
                _proc_v6_line(idx, "2001:db8::5", 9001, "2001:db8:bad::1", 48000 + k, "03", tx_q=0x1000, rx_q=0x4000)
            )
            idx += 1

    tcp4_path.write_text("\n".join(v4_lines) + "\n", encoding="utf-8")
    tcp6_path.write_text("\n".join(v6_lines) + "\n", encoding="utf-8")


def run_simulation(as_json: bool = False) -> list[dict]:
    """Execute all 4 local attack stages against live RelaySentry correlation engine."""
    with tempfile.TemporaryDirectory(prefix="relaysentry_sim_") as tmp:
        tmp_dir = Path(tmp)
        consensus_path = tmp_dir / "consensus.json"
        cookie_path = tmp_dir / "control_auth_cookie"
        tcp4_path = tmp_dir / "proc_tcp"
        tcp6_path = tmp_dir / "proc_tcp6"

        _write_consensus_fixture(consensus_path)
        cookie_bytes = b"RelaySentrySim32ByteAuthCookie!!"
        cookie_path.write_bytes(cookie_bytes)

        server = _MockRelayTelemetry(cookie_bytes)
        server.start()
        try:
            ports = {9001, 9030}
            consensus = load_consensus_index(consensus_file=consensus_path, no_cache=True, offline=True)
            vault = EphemeralPrivacyVault(reveal_flooders=True, flood_threshold=25)
            state_machine = DefenseStateMachine(hold_seconds=60.0)
            ring_buffer = TelemetryRingBuffer(maxlen=16)
            shield_controller = ShieldController(
                ports=ports,
                consensus_ips=consensus.ip_to_fps.keys(),
                backend="nft",
                dry_run=True,
                ban_ttl_seconds=1800,
                flood_threshold=25,
            )

            args = argparse.Namespace(
                proc_tcp_file=tcp4_path,
                proc_tcp6_file=tcp6_path,
                metrics_url=f"http://127.0.0.1:{server.metrics_port}/metrics",
                metrics_timeout=0.25,
                control_host="127.0.0.1",
                control_port=server.control_port,
                control_cookie=cookie_path,
                flood_threshold=25,
                emit_nft_hints=True,
                max_exact_sockets=50000,
            )

            stage_specs = [
                (
                    "baseline",
                    "Stage 1: Healthy Tor Relay Baseline",
                    False,
                    dict(
                        conn_or=85,
                        conn_dir=20,
                        sock_tot=45,
                        ntor_proc=12000,
                        ntor_drop=0,
                        oom_bytes=0,
                        begindir_rate_rej=0,
                        begindir_rej=0,
                        begindir_hsdir_rej=0,
                        circuit_killed=0,
                        conn_rej=0,
                        begindir_streams=40,
                    ),
                ),
                (
                    "thunderstorm_classic",
                    "Stage 2: Classic BEGIN_DIR Thunderstorm (Pre/Post 0.4.9.15 Counters)",
                    False,
                    dict(
                        conn_or=210,
                        conn_dir=640,
                        sock_tot=850,
                        ntor_proc=15500,
                        ntor_drop=2400,
                        oom_bytes=0,
                        begindir_rate_rej=420,
                        begindir_rej=65,
                        begindir_hsdir_rej=180,
                        circuit_killed=8,
                        conn_rej=12,
                        begindir_streams=1440,
                    ),
                ),
                (
                    "half_open_bypass",
                    "Stage 3: Post-0.4.9.16 Half-Open BEGIN_DIR Bypass + Stalled Event Loop",
                    True,
                    dict(
                        conn_or=240,
                        conn_dir=980,
                        sock_tot=1400,
                        ntor_proc=15500,
                        ntor_drop=2400,
                        oom_bytes=0,
                        begindir_rate_rej=420,
                        begindir_rej=65,
                        begindir_hsdir_rej=180,
                        circuit_killed=8,
                        conn_rej=12,
                        begindir_streams=1440,
                    ),
                ),
                (
                    "distributed_nonrelay",
                    "Stage 4: Distributed Non-Relay SYN/Queue Flood + OOM + Client Privacy",
                    False,
                    dict(
                        conn_or=920,
                        conn_dir=1020,
                        sock_tot=2600,
                        ntor_proc=18000,
                        ntor_drop=3900,
                        oom_bytes=8388608,
                        begindir_rate_rej=440,
                        begindir_rej=70,
                        begindir_hsdir_rej=190,
                        circuit_killed=50,
                        conn_rej=102,
                        begindir_streams=1580,
                    ),
                ),
            ]

            prev_metrics = None
            outputs: list[dict] = []

            for stage_id, title, inject_stall, metric_kwargs in stage_specs:
                _write_proc_stage(tcp4_path, tcp6_path, stage_id)
                with server.lock:
                    server.stall_metrics = inject_stall
                    server.stall_control = inject_stall
                    server.metrics_body = _render_prometheus(**metric_kwargs)
                    server.orconn_lines = [
                        "$" + "B" * 40 + "=GuardHSDirA1 CONNECTED",
                        "$" + "D" * 40 + "=GuardHSDirB1 LAUNCHED",
                    ]

                report, prev_metrics = run_once(
                    ports,
                    consensus,
                    vault,
                    args,
                    prev_metrics,
                    state_machine=state_machine,
                    ring_buffer=ring_buffer,
                    shield_controller=shield_controller,
                )

                # Stage assertions verifying real-world detection accuracy and privacy invariants
                assert not any(p.label == "203.0.113.40" or (not p.masked and p.label == "203.0.113.40") for p in report.nonrelay_peers), (
                    f"{stage_id}: honest 2-socket Tor client IP must stay strictly masked"
                )
                shield_sum = shield_controller.last_summary
                assert shield_sum is not None
                assert "192.0.2.10" not in shield_controller.active_bans
                assert "198.51.100.11" not in shield_controller.active_bans
                assert "203.0.113.40" not in shield_controller.active_bans
                if stage_id == "baseline":
                    assert report.effective_severity == "NORMAL"
                    assert not report.metrics_unresponsive
                    assert shield_sum.consensus_synced is True
                    assert shield_sum.active_ban_count == 0
                elif stage_id == "thunderstorm_classic":
                    assert report.effective_severity == "ACTIVE_DOS_PRESSURE"
                    assert report.metrics_delta is not None and report.metrics_delta.begindir_rejected_delta == 665
                    assert any("THUNDERSTORM_BEGIN_DIR_FLOOD" in r for r in report.reasons)
                    assert any("DoSBeginDirRateEnabled 1" in h for h in report.tor_defense_hints)
                    assert shield_sum.active_ban_count == 0, "Consensus relay surges must NEVER ban relays"
                elif stage_id == "half_open_bypass":
                    assert report.metrics_unresponsive is True
                    assert report.control_unresponsive is True
                    assert prev_metrics is not None, "Previous MetricsPort snapshot must survive transient stall"
                    assert report.effective_severity == "ACTIVE_DOS_PRESSURE"
                    assert any("METRICS_PORT_UNRESPONSIVE" in r for r in report.reasons)
                    assert any("HALF_OPEN_BEGIN_DIR_BYPASS_SUSPECTED" in r for r in report.reasons)
                    assert any("high_order_alloc_disable=1" in h for h in report.tor_defense_hints)
                elif stage_id == "distributed_nonrelay":
                    assert report.metrics_unresponsive is False
                    assert report.control_unresponsive is False
                    assert report.effective_severity == "ACTIVE_DOS_PRESSURE"
                    assert report.flood_shape == "DISTRIBUTED_BOTNET"
                    assert report.metrics_delta is not None and report.metrics_delta.circuit_killed_delta == 42
                    assert any("TOR_CIRCUIT_CELL_DOS_TRIGGERS" in r for r in report.reasons)
                    assert any("TOR_OOM_TRIGGERED" in r for r in report.reasons)
                    assert any("2001:db8:bad::1" in h for h in report.nft_hints)
                    assert "2001:db8:bad::1" in shield_sum.added_bans
                    assert "2001:db8:bad::1" in shield_controller.active_bans

                nft_consensus = generate_nft_consensus_sync(consensus.ip_to_fps.keys(), ports)
                assert "set known_relays4" in nft_consensus and "192.0.2.10" in nft_consensus
                assert "set known_relays6" in nft_consensus and "2001:db8:1::13" in nft_consensus
                xdp_c = render_xdp_shield_c(ports)
                assert 'SEC("xdp")' in xdp_c

                entry = {"stage": stage_id, "title": title, "report": _report_to_dict(report, shield_status=shield_sum)}
                outputs.append(entry)
                if not as_json:
                    print(f"\n>>> {title}")
                    print(format_terminal_report(report, top_n=5, shield_status=shield_sum))

            if as_json:
                print(json.dumps(outputs, indent=2))
            else:
                print("\n[SIMULATION PASS] All 4 Thunderstorm & half-open bypass stages verified cleanly.")
            return outputs
        finally:
            server.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RelaySentry 4-stage Tor DoS Thunderstorm simulation runner")
    parser.add_argument("--json", action="store_true", help="Print full structured JSON array across all stages")
    args = parser.parse_args(argv)
    run_simulation(as_json=args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
