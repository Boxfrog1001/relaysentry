#!/usr/bin/env python3
"""Offline & loopback sandbox verification suite for RelaySentry."""

import argparse
import gzip
import hashlib
import http.server
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "test"))

import consensus_index
import simulate_thunderstorm
from consensus_index import ConsensusIndex, _write_secure_cache
from correlator import correlate_triage
from privacy_vault import EphemeralPrivacyVault, normalize_ip
from relaysentry import main as cli_main, run_once
from shield_engine import (
    DefenseStateMachine,
    ShieldController,
    TelemetryRingBuffer,
    classify_flood_shape,
    compute_shannon_entropy,
    generate_nft_consensus_sync,
    generate_xdp_map_sync,
    render_xdp_shield_c,
)
from telemetry_procfs import (
    decode_proc_addr,
    parse_proc_net_tcp_lines,
    parse_proc_net_tcp_lines_bounded,
)
from telemetry_tor import (
    MAX_METRICS_BYTES,
    OrConnEntry,
    TorMetricsSnapshot,
    fetch_metrics_port,
    parse_orconn_lines,
    parse_prometheus_metrics,
    query_control_orconn,
)


def _encode_ipv4_hex_le(ip_str: str) -> str:
    import ipaddress

    raw = ipaddress.IPv4Address(ip_str).packed
    return raw[::-1].hex().upper()


def _encode_ipv6_hex_le_words(ip_str: str) -> str:
    import ipaddress

    raw = ipaddress.IPv6Address(ip_str).packed
    return b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4)).hex().upper()


def test_procfs_decoding() -> None:
    print("[TEST 1] Verifying /proc/net/tcp & /proc/net/tcp6 hex decoding & states...")
    assert decode_proc_addr("0100007F:2329") == ("127.0.0.1", 9001)
    assert decode_proc_addr(f"{_encode_ipv4_hex_le('198.51.100.42')}:01BB") == ("198.51.100.42", 443)
    assert decode_proc_addr(f"{_encode_ipv6_hex_le_words('2001:db8:cafe::1')}:2329") == ("2001:db8:cafe::1", 9001)
    assert decode_proc_addr("00000000000000000000000001000000:A7D9") == ("::1", 0xA7D9)
    assert decode_proc_addr("0000000000000000FFFF00000100007F:8247") == ("127.0.0.1", 0x8247)
    # IPv4-mapped IPv6 (::ffff:10.0.0.5 in Linux 4x u32 little-endian format) normalizes cleanly to IPv4
    assert decode_proc_addr("0000000000000000FFFF00000500000A:2329") == ("10.0.0.5", 9001)

    sample_lines = [
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
        f"   0: 00000000:2329 00000000:0000 0A 00000000:00000000 00:00000000 00000000 105 0 100",
        f"   1: {_encode_ipv4_hex_le('203.0.113.10')}:2329 {_encode_ipv4_hex_le('198.51.100.2')}:A001 01 00000100:00000800 00:00000000 00000000 105 0 101",
        f"   2: {_encode_ipv4_hex_le('203.0.113.10')}:2329 {_encode_ipv4_hex_le('198.51.100.9')}:A002 03 00000000:00000000 00:00000000 00000000 105 0 102",
        f"   3: {_encode_ipv4_hex_le('203.0.113.10')}:0016 {_encode_ipv4_hex_le('192.0.2.55')}:BEEF 01 00000000:00000000 00:00000000 00000000 0 0 103",
    ]
    parsed = parse_proc_net_tcp_lines(sample_lines, {9001})
    assert len(parsed) == 2  # LISTEN and port 22 SSH excluded
    assert parsed[0].remote_ip == "198.51.100.2" and parsed[0].state == "ESTABLISHED"
    assert parsed[0].tx_queue == 0x100 and parsed[0].rx_queue == 0x800
    assert parsed[1].remote_ip == "198.51.100.9" and parsed[1].state == "SYN_RECV"
    print("  [PASS] procfs IPv4/IPv6/queue/state decoding verified.")


def test_privacy_vault_invariants() -> None:
    print("[TEST 2] Verifying strict Tor client IP masking & flood-threshold reveal gate...")
    honest_ip = "198.51.100.77"
    flooder_ip = "198.51.100.250"

    strict_vault = EphemeralPrivacyVault(reveal_flooders=False, flood_threshold=25)
    assert strict_vault.classify_nonrelay(honest_ip, 2).disclosed_ip is None
    assert strict_vault.classify_nonrelay(flooder_ip, 500).disclosed_ip is None

    # Different session vault MUST generate a distinct random HMAC key
    strict_vault_2 = EphemeralPrivacyVault(reveal_flooders=False, flood_threshold=25)
    assert strict_vault.anonymize_ip(honest_ip) != strict_vault_2.anonymize_ip(honest_ip)

    # Even in emergency --reveal-flooders mode, honest 2-socket clients stay masked!
    emergency_vault = EphemeralPrivacyVault(reveal_flooders=True, flood_threshold=25)
    honest_lbl = emergency_vault.classify_nonrelay(honest_ip, 2)
    flood_lbl = emergency_vault.classify_nonrelay(flooder_ip, 40)
    assert honest_lbl.masked is True and honest_lbl.disclosed_ip is None
    assert flood_lbl.masked is False and flood_lbl.disclosed_ip == flooder_ip
    print("  [PASS] Honest low-connection IPs remain cryptographically masked in all modes.")


def test_consensus_attribution_and_cluster_rollup() -> None:
    print("[TEST 3] Verifying Consensus Relay & effective_family attribution under DoS wave...")
    fp_a = "A" * 40
    fp_b = "B" * 40
    payload = {
        "relays": [
            {
                "nickname": "EvilRelayOne",
                "fingerprint": fp_a,
                "running": True,
                "or_addresses": ["198.51.100.11:9001", "[2001:db8:1::11]:9001"],
                "flags": ["Fast", "Guard", "Running", "Valid"],
                "as": "AS64512",
                "as_name": "ExampleHost LLC",
                "effective_family": [f"${fp_a}", f"${fp_b}"],
                "consensus_weight": 5000,
                "version": "0.4.9.16",
            },
            {
                "nickname": "EvilRelayTwo",
                "fingerprint": fp_b,
                "running": True,
                "or_addresses": ["198.51.100.12:9001"],
                "flags": ["Fast", "HSDir", "Running", "Valid"],
                "as": "AS64512",
                "as_name": "ExampleHost LLC",
                "effective_family": [f"${fp_a}", f"${fp_b}"],
                "consensus_weight": 4200,
                "version": "0.4.9.16",
            },
        ]
    }
    consensus = ConsensusIndex.from_onionoo_payload(payload)
    assert normalize_ip("[2001:0db8:0001::11]:9001") == "2001:db8:1::11"
    assert len(consensus.lookup_ip("2001:db8:1::11")) == 1
    assert consensus.lookup_fp(fp_a).effective_family == (fp_b,)

    # Also verify Tor native cached-consensus v3 dir-spec format decoding
    v3_sample = (
        "network-status-version 3\n"
        "r test000a JirzEKh/FCRotTnGDcZb+ouUY9c og1ZnZ1ku0GY7ANxmjP8HAqmnJU "
        "2026-11-12 19:06:22 127.0.1.10 5000 7000\n"
        "s Authority Fast Guard HSDir Running Stable V2Dir Valid\n"
        "v Tor 0.4.9.11\n"
        "w Bandwidth=114 Unmeasured=1\n"
    )
    v3_idx = ConsensusIndex.from_cached_consensus(v3_sample)
    v3_meta = v3_idx.lookup_ip("127.0.1.10")
    assert len(v3_meta) == 1
    assert v3_meta[0].fingerprint == "262AF310A87F142468B539C60DC65BFA8B9463D7"
    assert v3_meta[0].nickname == "test000a" and v3_meta[0].consensus_weight == 114

    # Simulate 30 sockets from EvilRelayOne + 28 from EvilRelayTwo + 35 from raw botnet + 2 from honest client
    lines = []
    idx = 0
    for i in range(30):
        lines.append(f" {idx}: {_encode_ipv4_hex_le('203.0.113.10')}:2329 {_encode_ipv4_hex_le('198.51.100.11')}:{30000+i:04X} 01 00000000:00010000 00:00000000 0 105 0 10")
        idx += 1
    for i in range(28):
        lines.append(f" {idx}: {_encode_ipv4_hex_le('203.0.113.10')}:2329 {_encode_ipv4_hex_le('198.51.100.12')}:{31000+i:04X} 01 00000000:00010000 00:00000000 0 105 0 10")
        idx += 1
    for i in range(35):
        lines.append(f" {idx}: {_encode_ipv4_hex_le('203.0.113.10')}:2329 {_encode_ipv4_hex_le('192.0.2.200')}:{32000+i:04X} 03 00000000:00000000 00:00000000 0 105 0 10")
        idx += 1
    for i in range(2):
        lines.append(f" {idx}: {_encode_ipv4_hex_le('203.0.113.10')}:2329 {_encode_ipv4_hex_le('192.0.2.50')}:{33000+i:04X} 01 00000000:00000000 00:00000000 0 105 0 10")
        idx += 1

    sockets = parse_proc_net_tcp_lines(lines, {9001})
    vault = EphemeralPrivacyVault(reveal_flooders=True, flood_threshold=25)
    prev = TorMetricsSnapshot(ntor_processed=1000, ntor_dropped=0, oom_bytes_total=0)
    curr = TorMetricsSnapshot(ntor_processed=1200, ntor_dropped=300, oom_bytes_total=4194304, socket_total=95)
    report = correlate_triage(
        sockets=sockets,
        consensus=consensus,
        vault=vault,
        metrics_curr=curr,
        metrics_prev=prev,
        flood_threshold=25,
        emit_nft_hints=True,
    )
    assert report.severity == "ACTIVE_DOS_PRESSURE"
    assert report.consensus_socket_total == 58
    assert report.nonrelay_socket_total == 37
    assert len(report.cluster_rollups) == 1
    assert report.cluster_rollups[0].relay_count == 2
    assert report.cluster_rollups[0].total_sockets == 58
    assert report.nonrelay_peers[0].label == "192.0.2.200"  # revealed flooder >= 25
    assert report.nonrelay_peers[1].masked is True  # honest 2-socket client stayed masked!
    assert "192.0.2.50" not in report.nonrelay_peers[1].label
    assert len(report.nft_hints) == 1
    assert "relaysentry_hints" in report.nft_hints[0]
    assert "192.0.2.200" in report.nft_hints[0] and "limit rate" in report.nft_hints[0]
    assert report.flood_shape == "CONCENTRATED_SOURCE"
    assert report.tor_defense_hints, "Expected actionable Tor PoW/kernel defense guidance"
    print("  [PASS] Family cluster rollup, threshold gating, MetricsPort delta & nft hint verified.")


def test_loopback_metricsport_and_controlport() -> None:
    print("[TEST 4] Verifying live loopback MetricsPort & ControlPort readers + size bounds...")
    prom_body = (
        '# HELP tor_relay_load_onionskins_total Total number of onionskins.\n'
        'tor_relay_connections{type="OR listener",direction="initiated",state="opened",family="ipv4"} 1\n'
        'tor_relay_connections{type="OR",direction="received",state="opened",family="ipv4"} 124\n'
        'tor_relay_connections{type="Directory",direction="received",state="opened",family="ipv4"} 18\n'
        'tor_relay_load_onionskins_total{type="ntor",action="processed"} 9500\n'
        'tor_relay_load_onionskins_total{type="ntor",action="dropped"} 500\n'
        'tor_relay_load_oom_bytes_total 1048576\n'
        'tor_relay_load_socket_total{state="opened"} 880\n'
        'tor_relay_load_socket_total 524256\n'
    )

    class MetricsHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = prom_body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), MetricsHandler)
    m_port = httpd.server_address[1]
    t_http = threading.Thread(target=httpd.serve_forever, daemon=True)
    t_http.start()

    # Fake ControlPort server expecting 32-byte cookie auth
    cookie_bytes = os.urandom(32)
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(1)
    c_port = srv_sock.getsockname()[1]

    def control_loop():
        conn, _ = srv_sock.accept()
        with conn:
            auth_line = conn.recv(512).decode()
            if cookie_bytes.hex() in auth_line.lower():
                conn.sendall(b"250 OK\r\n")
            else:
                conn.sendall(b"515 Bad authentication\r\n")
                return
            cmd = conn.recv(512).decode()
            if "orconn-status" in cmd:
                conn.sendall(
                    b"250+orconn-status=\r\n"
                    b"$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~EvilRelayOne CONNECTED\r\n"
                    b".\r\n"
                    b"250 OK\r\n"
                )
            conn.recv(128)

    t_ctrl = threading.Thread(target=control_loop, daemon=True)
    t_ctrl.start()

    try:
        snap = fetch_metrics_port(f"http://127.0.0.1:{m_port}/metrics")
        assert snap.or_connections_opened == 124 and snap.dir_connections_opened == 18
        assert snap.connections_opened == 142 and snap.socket_total == 880
        assert snap.ntor_processed == 9500 and snap.ntor_dropped == 500
        assert abs(snap.drop_ratio_pct - 5.0) < 0.01
        assert snap.oom_bytes_total == 1048576

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(cookie_bytes)
            cookie_path = Path(tf.name)
        try:
            conns = query_control_orconn("127.0.0.1", c_port, cookie_path=cookie_path)
            assert len(conns) == 1
            assert conns[0].fingerprint == "A" * 40 and conns[0].status == "CONNECTED"
        finally:
            cookie_path.unlink(missing_ok=True)
    finally:
        httpd.shutdown()
        httpd.server_close()
        srv_sock.close()

    assert parse_orconn_lines(["500 bad", "$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=TestRel LAUNCHED"])[0].nickname == "TestRel"
    print("  [PASS] Loopback MetricsPort, ControlPort 32-byte cookie auth, and ORCONN parsing verified.")


def test_cache_permissions_and_cli_json() -> None:
    print("[TEST 5] Verifying 0600 atomic cache hardening and full CLI offline replay...")
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        cache_file = td_path / "cache" / "onionoo.json"
        _write_secure_cache(cache_file, b'{"relays":[]}')
        mode = stat.S_IMODE(cache_file.stat().st_mode)
        assert mode == 0o600, f"Expected 0600, got {oct(mode)}"

        cons_file = td_path / "cons.json"
        cons_file.write_text(
            json.dumps(
                {
                    "relays": [
                        {
                            "nickname": "PeerGuard1",
                            "fingerprint": "C" * 40,
                            "running": True,
                            "or_addresses": ["198.51.100.33:9001"],
                            "flags": ["Guard", "Running", "Valid"],
                            "as": "AS64599",
                            "as_name": "GuardNet",
                            "consensus_weight": 1000,
                        }
                    ]
                }
            )
        )
        proc_file = td_path / "tcp"
        proc_file.write_text(
            "\n".join(
                [
                    "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode",
                    f"   0: {_encode_ipv4_hex_le('203.0.113.5')}:2329 {_encode_ipv4_hex_le('198.51.100.33')}:AA01 01 00000000:00000400 00:00000000 0 105 0 1",
                    f"   1: {_encode_ipv4_hex_le('203.0.113.5')}:2329 {_encode_ipv4_hex_le('192.0.2.88')}:AA02 01 00000000:00000000 00:00000000 0 105 0 2",
                ]
            )
        )
        rc = cli_main(
            [
                "--port",
                "9001",
                "--consensus-file",
                str(cons_file),
                "--proc-tcp-file",
                str(proc_file),
                "--no-cache",
                "--json",
            ]
        )
        assert rc == 0
    print("  [PASS] 0600 cache file permissions and end-to-end CLI JSON replay verified.")


def test_cache_ttl_gzip_multiorconn_and_interrupt() -> None:
    print("[TEST 6] Verifying gzip Onionoo fetch, 1h cache TTL/--refresh, multi-IP ORCONN & Ctrl+C exit...")
    fp_gzip = "D" * 40
    fp_inst1 = "1" * 40
    fp_inst2 = "2" * 40
    onionoo_bytes = gzip.compress(
        json.dumps(
            {
                "relays": [
                    {
                        "nickname": "GzipRelay",
                        "fingerprint": fp_gzip,
                        "running": True,
                        "or_addresses": ["198.51.100.77:9001"],
                        "flags": ["Guard", "Running", "Valid"],
                        "as": "AS64555",
                        "as_name": "GzipNet",
                        "consensus_weight": 777,
                    }
                ]
            }
        ).encode("utf-8")
    )
    hits: list[str] = []

    ua_headers: list[str] = []

    class GzipOnionooHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            hits.append(self.path)
            ua_headers.append(self.headers.get("User-Agent", ""))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(onionoo_bytes)))
            self.end_headers()
            self.wfile.write(onionoo_bytes)

        def log_message(self, *args) -> None:
            return

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), GzipOnionooHandler)
    srv_port = httpd.server_address[1]
    t_srv = threading.Thread(target=httpd.serve_forever, daemon=True)
    t_srv.start()

    orig_url = consensus_index.ONIONOO_DETAILS_URL
    try:
        consensus_index.ONIONOO_DETAILS_URL = f"http://127.0.0.1:{srv_port}/details"
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            cache_file = td_path / "cache" / "onionoo.json"

            idx1 = consensus_index.load_consensus_index(
                cache_path=cache_file,
                cache_ttl_seconds=3600,
                offline=False,
            )
            assert len(hits) == 1 and "fields=" in hits[0]
            assert idx1.lookup_fp(fp_gzip) is not None
            assert stat.S_IMODE(cache_file.stat().st_mode) == 0o600

            # Warm 0600 cache (< 3600s) must be reused without hitting network.
            idx2 = consensus_index.load_consensus_index(
                cache_path=cache_file,
                cache_ttl_seconds=3600,
                offline=False,
            )
            assert len(hits) == 1
            assert idx2.lookup_fp(fp_gzip) is not None

            # refresh=True must bypass warm cache and fetch again cleanly.
            idx3 = consensus_index.load_consensus_index(
                cache_path=cache_file,
                cache_ttl_seconds=3600,
                refresh=True,
                offline=False,
            )
            assert len(hits) == 2
            assert ua_headers == ["RelaySentry/0.3", "RelaySentry/0.3"]
            assert idx3.lookup_fp(fp_gzip) is not None
            assert list((td_path / "cache").glob("*.tmp")) == []

            # Verify multi-instance shared IP resolves ORCONN even when matched on 2nd relay fp.
            multi_cons = ConsensusIndex.from_onionoo_payload(
                {
                    "relays": [
                        {
                            "nickname": "InstOne",
                            "fingerprint": fp_inst1,
                            "running": True,
                            "or_addresses": ["198.51.100.77:9001"],
                            "flags": ["Guard", "Running"],
                        },
                        {
                            "nickname": "InstTwo",
                            "fingerprint": fp_inst2,
                            "running": True,
                            "or_addresses": ["198.51.100.77:9001"],
                            "flags": ["Fast", "Running"],
                        },
                    ]
                }
            )
            socks = parse_proc_net_tcp_lines(
                [
                    f"   0: {_encode_ipv4_hex_le('203.0.113.5')}:2329 {_encode_ipv4_hex_le('198.51.100.77')}:AA01 01 00000000:00000000 00:00000000 0 105 0 1"
                ],
                {9001},
            )
            rep = correlate_triage(
                sockets=socks,
                consensus=multi_cons,
                vault=EphemeralPrivacyVault(),
                orconns=[OrConnEntry(fingerprint=fp_inst2, nickname="InstTwo", status="CONNECTED")],
            )
            assert len(rep.consensus_peers) == 1
            assert rep.consensus_peers[0].orconn_state == "CONNECTED"

            # Verify --watch KeyboardInterrupt exits cleanly with rc == 0.
            cons_file = td_path / "cons.json"
            cons_file.write_text(json.dumps({"relays": []}))
            proc_file = td_path / "tcp"
            proc_file.write_text("  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n")
            with mock.patch("time.sleep", side_effect=KeyboardInterrupt):
                rc = cli_main(
                    [
                        "--port",
                        "9001",
                        "--consensus-file",
                        str(cons_file),
                        "--proc-tcp-file",
                        str(proc_file),
                        "--no-cache",
                        "--watch",
                        "1",
                    ]
                )
            assert rc == 0
    finally:
        consensus_index.ONIONOO_DETAILS_URL = orig_url
        httpd.shutdown()
        httpd.server_close()

    print("  [PASS] Gzip Onionoo, 1h cache TTL reuse/--refresh, multi-IP ORCONN & Ctrl+C exit verified.")


def test_security_hardening_boundaries() -> None:
    print("[TEST 7] Verifying CWE-409 gzip bomb guard, CWE-400 file caps & SSRF redirect blocks...")
    # 1. CWE-409: streaming gzip decompression cap stops bombs early + supports multi-member gzip
    multi = gzip.compress(b'{"relays":') + gzip.compress(b"[]}")
    assert consensus_index._decompress_gzip_bounded(multi, 1024, "test") == b'{"relays":[]}'
    bomb = gzip.compress(b"\x00" * 100000)
    bomb_blocked = False
    try:
        consensus_index._decompress_gzip_bounded(bomb, 4096, "bomb")
    except ValueError:
        bomb_blocked = True
    assert bomb_blocked, "Expected ValueError on decompressed size overflow"

    # 2. CWE-400: pre-read file caps for consensus and procfs fixtures
    import relaysentry as relaysentry_mod

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        big_file = td_path / "big.json"
        big_file.write_bytes(b"A" * 5000)
        cap_hit = False
        try:
            consensus_index._read_bounded_file(big_file, 1024, "big")
        except ValueError:
            cap_hit = True
        assert cap_hit

        orig_proc_max = relaysentry_mod.MAX_PROCFS_FILE_BYTES
        try:
            relaysentry_mod.MAX_PROCFS_FILE_BYTES = 500
            proc_big = td_path / "big_tcp"
            proc_big.write_text("0: 0100007F:2329 0100007F:AAAA 01\n" * 40)
            proc_cap_hit = False
            try:
                relaysentry_mod._read_bounded_procfs_fixture(proc_big, {9001})
            except ValueError:
                proc_cap_hit = True
            assert proc_cap_hit
        finally:
            relaysentry_mod.MAX_PROCFS_FILE_BYTES = orig_proc_max

    # 3. SSRF / downgrade HTTP redirect rejection on MetricsPort & Onionoo
    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()

        def log_message(self, *args) -> None:
            return

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    r_port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    orig_url = consensus_index.ONIONOO_DETAILS_URL
    try:
        m_blocked = False
        try:
            fetch_metrics_port(f"http://127.0.0.1:{r_port}/metrics")
        except ValueError:
            m_blocked = True
        assert m_blocked, "MetricsPort 302 redirect must be blocked"

        consensus_index.ONIONOO_DETAILS_URL = f"http://127.0.0.1:{r_port}/details"
        o_blocked = False
        try:
            consensus_index.load_consensus_index(no_cache=True, offline=False)
        except ValueError:
            o_blocked = True
        assert o_blocked, "Unsafe Onionoo HTTP redirect must be blocked"
    finally:
        consensus_index.ONIONOO_DETAILS_URL = orig_url
        httpd.shutdown()
        httpd.server_close()

    print("  [PASS] Gzip bomb bound, pre-read file caps, and SSRF redirect rejections verified.")


def test_adaptive_shield_xdp_entropy_and_stride() -> None:
    print("[TEST 8] Verifying hysteresis shield, entropy classifier, 1-in-16 stride privacy & XDP C...")
    # 1. Three-state hysteresis machine prevents oscillation across pulsing floods
    sm = DefenseStateMachine(hold_seconds=60.0)
    assert sm.step("NORMAL", now_monotonic=0.0) == ("NORMAL", 0.0)
    assert sm.step("ACTIVE_DOS_PRESSURE", now_monotonic=10.0) == ("ACTIVE_DOS_PRESSURE", 0.0)
    eff, rem = sm.step("NORMAL", now_monotonic=30.0)
    assert eff == "ACTIVE_DOS_PRESSURE" and abs(rem - 40.0) < 0.01
    assert sm.step("NORMAL", now_monotonic=71.0) == ("NORMAL", 0.0)

    # 2. Shannon entropy & flood-shape classification
    assert classify_flood_shape([50, 1, 1], 52)[0] == "CONCENTRATED_SOURCE"
    shape_dist, h_dist = classify_flood_shape([2] * 64, 128)
    assert shape_dist == "DISTRIBUTED_BOTNET" and abs(h_dist - 6.0) < 0.01

    # 3. 1-in-16 overload stride sampling keeps 1-socket honest clients masked!
    flood_lines = []
    # 90 sockets from flooder 192.0.2.250 + 1 single socket from honest 192.0.2.44
    for i in range(90):
        flood_lines.append(
            f" {i}: {_encode_ipv4_hex_le('203.0.113.5')}:2329 "
            f"{_encode_ipv4_hex_le('192.0.2.250')}:{40000 + i:04X} 03 00000000:00000000 00:00000000 0 105 0 1"
        )
    # Place honest socket at exact stride multiple index=96 by padding 6 lines cleanly
    for i in range(6):
        flood_lines.append(
            f" {90+i}: {_encode_ipv4_hex_le('203.0.113.5')}:2329 "
            f"{_encode_ipv4_hex_le('192.0.2.251')}:{41000 + i:04X} 01 00000000:00000000 00:00000000 0 105 0 1"
        )
    flood_lines.append(
        f" 96: {_encode_ipv4_hex_le('203.0.113.5')}:2329 "
        f"{_encode_ipv4_hex_le('192.0.2.44')}:9999 01 00000000:00000000 00:00000000 0 105 0 1"
    )
    sampled, stride = parse_proc_net_tcp_lines_bounded(
        flood_lines, {9001}, max_exact_sockets=32, overload_stride=16
    )
    assert stride == 16 and len(sampled) == 7  # indices 0,16,32,48,64,80,96
    ring = TelemetryRingBuffer(maxlen=3)
    vault = EphemeralPrivacyVault(reveal_flooders=True, flood_threshold=10)
    rep = correlate_triage(
        sockets=sampled,
        consensus=ConsensusIndex({}, {}),
        vault=vault,
        flood_threshold=10,
        emit_nft_hints=True,
        sample_stride=stride,
        state_machine=sm,
        ring_buffer=ring,
    )
    assert rep.sample_stride == 16
    assert rep.total_monitored_sockets == 7 * 16
    labels = {p.label: p.masked for p in rep.nonrelay_peers}
    assert "192.0.2.250" in labels and labels["192.0.2.250"] is False
    # Honest single sampled client at index 96 MUST stay masked even though 1*16 >= 10!
    assert "192.0.2.44" not in labels
    assert sum(1 for p in rep.nonrelay_peers if p.masked) == 1
    for j in range(5):
        ring.push(ring.snapshot()[-1])
    assert len(ring.snapshot()) == 3

    # 4. Dual-stack XDP/eBPF C shield template generation + CLI --emit-xdp-c exit 0
    xdp_src = render_xdp_shield_c({9001, 9030})
    assert 'SEC("xdp")' in xdp_src
    assert "allow_relay_v4" in xdp_src and "allow_relay_v6" in xdp_src
    assert "blocked_v4" in xdp_src and "blocked_v6" in xdp_src
    assert "BPF_MAP_TYPE_LRU_HASH" in xdp_src
    assert "dport == 9001 || dport == 9030" in xdp_src
    assert cli_main(["--port", "9001", "--emit-xdp-c"]) == 0
    print("  [PASS] Hysteresis, Shannon flood classifier, 1-in-16 stride privacy & XDP C verified.")


def test_thunderstorm_and_unresponsive_metrics_resilience() -> None:
    print("[TEST 9] Verifying BEGIN_DIR Thunderstorm, bypass stall, MetricsPort timeout resilience & consensus nft...")
    # 1. Verify full Prometheus DoS metric family & BEGIN_DIR stream parsing + delta tracking
    m_prev = parse_prometheus_metrics(
        "\n".join(
            [
                'tor_relay_dos_total{type="begindir_rate_rejected"} 100',
                'tor_relay_dos_total{type="begindir_rejected"} 20',
                'tor_relay_dos_total{type="begindir_hsdir_rejected"} 10',
                'tor_relay_dos_total{type="circuit_killed_max_cell"} 5',
                'tor_relay_dos_total{type="circuit_killed_max_cell_outq"} 2',
                'tor_relay_dos_total{type="conn_rejected"} 3',
                'tor_relay_dos_total{type="concurrent_conn_rejected"} 4',
                'tor_relay_streams_total{cmd="BEGIN_DIR"} 500',
            ]
        )
    )
    m_curr = parse_prometheus_metrics(
        "\n".join(
            [
                'tor_relay_dos_total{type="begindir_rate_rejected"} 250',
                'tor_relay_dos_total{type="begindir_rejected"} 45',
                'tor_relay_dos_total{type="begindir_hsdir_rejected"} 35',
                'tor_relay_dos_total{type="circuit_killed_max_cell"} 12',
                'tor_relay_dos_total{type="circuit_killed_max_cell_outq"} 8',
                'tor_relay_dos_total{type="conn_rejected"} 20',
                'tor_relay_dos_total{type="concurrent_conn_rejected"} 14',
                'tor_relay_streams_total{cmd="BEGIN_DIR"} 1900',
            ]
        )
    )
    assert m_curr.total_begindir_rejected == 330
    assert m_curr.circuit_killed_max_cell == 20
    assert m_curr.conn_rejected == 34
    assert m_curr.begindir_streams_total == 1900

    # 2. Half-open BEGIN_DIR bypass check even when MetricsPort answers with 0 DoS rejections
    consensus_path_data = {
        "relays": [
            {
                "nickname": "AuthorityOne",
                "fingerprint": "A" * 40,
                "or_addresses": ["192.0.2.10:9001"],
                "flags": ["Authority", "V2Dir", "Valid", "Running"],
                "as": "AS64510",
                "as_name": "AuthNet",
                "effective_family": ["$" + "A" * 40],
            },
            {
                "nickname": "RelayStallPeer",
                "fingerprint": "B" * 40,
                "or_addresses": ["198.51.100.11:9001", "[2001:db8:1::11]:9001"],
                "flags": ["Fast", "Guard", "HSDir", "Valid", "Running"],
                "as": "AS64511",
                "as_name": "PeerNet",
                "effective_family": ["$" + "B" * 40],
            },
        ]
    }
    with tempfile.TemporaryDirectory(prefix="relaysentry_t9_") as td:
        tmp = Path(td)
        cons_file = tmp / "consensus.json"
        cons_file.write_text(json.dumps(consensus_path_data), encoding="utf-8")
        tcp_file = tmp / "tcp"
        tcp_file.write_text(
            "\n".join(
                [
                    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
                    *[
                        f" {i:3d}: {_encode_ipv4_hex_le('192.0.2.5')}:2329 "
                        f"{_encode_ipv4_hex_le('198.51.100.11')}:{40000 + i:04X} 01 00002000:00008000 00:00000000 0 105 0 {100 + i}"
                        for i in range(30)
                    ],
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        cons_idx = consensus_index.load_consensus_index(consensus_file=cons_file, no_cache=True, offline=True)
        vault = EphemeralPrivacyVault(reveal_flooders=False, flood_threshold=25)
        sockets = parse_proc_net_tcp_lines(tcp_file.read_text(encoding="utf-8").splitlines(), {9001})

        bypass_rep = correlate_triage(
            sockets=sockets,
            consensus=cons_idx,
            vault=vault,
            metrics_curr=m_prev,
            metrics_prev=m_prev,  # begindir_rejected_delta == 0 while heavy queues stall!
            flood_threshold=25,
        )
        assert any("HALF_OPEN_BEGIN_DIR_BYPASS_SUSPECTED" in r for r in bypass_rep.reasons)
        assert bypass_rep.severity == "ACTIVE_DOS_PRESSURE"

        # 3. ConnectionRefused / closed MetricsPort + ControlPort during run_once must NEVER crash --watch
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as unused:
            unused.bind(("127.0.0.1", 0))
            dead_port = unused.getsockname()[1]

        resilience_args = argparse.Namespace(
            proc_tcp_file=tcp_file,
            proc_tcp6_file=None,
            metrics_url=f"http://127.0.0.1:{dead_port}/metrics",
            metrics_timeout=0.25,
            control_host="127.0.0.1",
            control_port=dead_port,
            control_cookie=None,
            flood_threshold=25,
            emit_nft_hints=False,
            max_exact_sockets=50000,
        )
        stalled_rep, kept_prev = run_once(
            {9001}, cons_idx, vault, resilience_args, m_prev
        )
        assert stalled_rep.metrics_unresponsive is True
        assert stalled_rep.control_unresponsive is True
        assert kept_prev is m_prev
        assert any("METRICS_PORT_UNRESPONSIVE" in r for r in stalled_rep.reasons)
        assert any("CONTROL_PORT_UNRESPONSIVE" in r for r in stalled_rep.reasons)

        # 4. Dual-stack consensus nftables sync + CLI flag (per-IP dynamic sets + allow_net + connlimit + chunking)
        nft_script = generate_nft_consensus_sync(
            cons_idx.ip_to_fps.keys(),
            {9001, 9030},
            allow_cidrs=["198.51.100.0/24"],
        )
        assert "add table inet relaysentry_shield" in nft_script
        assert "delete table inet relaysentry_shield" in nft_script
        assert "set allow_net4" in nft_script and "flags interval" in nft_script
        assert "198.51.100.0/24" in nft_script and "127.0.0.0/8" in nft_script
        assert "set known_relays4" in nft_script and "set known_relays6" in nft_script
        assert "set tor_syn4" in nft_script and "set tor_syn6" in nft_script
        assert "add @tor_syn4 { ip saddr limit rate" in nft_script
        assert "set tor_ddos4" in nft_script and "set tor_ddos6" in nft_script
        assert "set connlimit4" in nft_script and "set connlimit6" in nft_script
        assert "flags dynamic, timeout" in nft_script and "size 65536" in nft_script
        assert "meter " not in nft_script, "Must use modern dynamic sets instead of deprecated meter syntax"
        assert "flush chain inet relaysentry_shield input" in nft_script
        assert "192.0.2.10" in nft_script and "2001:db8:1::11" in nft_script
        many_ips = [f"203.0.{i // 256}.{i % 256}" for i in range(600)]
        chunked_nft = generate_nft_consensus_sync(many_ips, {9001})
        assert chunked_nft.count("add element inet relaysentry_shield known_relays4") == 3
        assert cli_main(
            ["--port", "9001", "--consensus-file", str(cons_file), "--offline", "--no-cache", "--emit-nft-consensus"]
        ) == 0

    # 5. Full 4-stage live Thunderstorm + half-open stall simulation must complete cleanly
    assert simulate_thunderstorm.main([]) == 0
    print("  [PASS] Thunderstorm detection, bypass resilience, consensus nft sync & simulator verified.")


def test_builtin_shield_controller_and_xdp_sync() -> None:
    print("[TEST 10] Verifying built-in ShieldController (nft/XDP), --emit-xdp-sync & dry-run enforcement...")
    # 1. bpftool hex batch generation & Consensus exemption
    xdp_batch = generate_xdp_map_sync(
        consensus_ips=["192.0.2.10", "2001:db8:1::11"],
        blocked_ips=["192.0.2.10", "203.0.113.200", "2001:db8:bad::1"],
        pin_dir="/sys/fs/bpf/relaysentry/",
        unblock_ips=["203.0.113.201"],
    )
    assert "map update pinned /sys/fs/bpf/relaysentry/allow_relay_v4 key hex c0 00 02 0a value hex 01 any" in xdp_batch
    assert "allow_relay_v6 key hex 20 01 0d b8 00 01 00 00 00 00 00 00 00 00 00 11 value hex 01 any" in xdp_batch
    assert "blocked_v4 key hex cb 00 71 c8 value hex 00 00 00 00 00 00 00 00 any" in xdp_batch
    assert "blocked_v6 key hex 20 01 0d b8 0b ad 00 00 00 00 00 00 00 00 00 01 value hex 00 00 00 00 00 00 00 00 any" in xdp_batch
    assert "blocked_v4 key hex c0 00 02 0a" not in xdp_batch, "Consensus IP must never enter blocked_v4"
    assert "map delete pinned /sys/fs/bpf/relaysentry/blocked_v4 key hex cb 00 71 c9" in xdp_batch

    bad_pin = False
    try:
        generate_xdp_map_sync([], pin_dir="/sys/fs/bpf/bad;rm")
    except ValueError:
        bad_pin = True
    assert bad_pin

    # 2. Live ShieldController nft backend (simulated kernel runner): sync + flood ban + exemptions + NORMAL cleanup
    nft_calls: list[tuple[list[str], str]] = []
    nft_ctrl = ShieldController(
        ports={9001, 9030},
        consensus_ips=["192.0.2.10", "2001:db8:1::11"],
        backend="auto",
        dry_run=False,
        ban_ttl_seconds=1800,
        flood_threshold=25,
        allow_cidrs=["198.51.100.0/24"],
        command_runner=lambda argv, payload: nft_calls.append((argv, payload)),
        backend_detector=lambda: "nft",
    )
    s1 = nft_ctrl.reconcile(
        "ACTIVE_DOS_PRESSURE",
        ["192.0.2.10", "127.0.0.1", "198.51.100.55", "203.0.113.200", "2001:db8:bad::1"],
        now_monotonic=100.0,
    )
    assert s1.backend == "nft" and s1.consensus_synced is True
    assert s1.skipped_protected == 3
    assert s1.added_bans == ("203.0.113.200", "2001:db8:bad::1")
    assert s1.active_ban_count == 2
    assert nft_calls[-1][0] == ["nft", "-f", "-"]
    assert "allow_net4" in nft_calls[-1][1] and "198.51.100.0/24" in nft_calls[-1][1]
    assert "add @tor_syn4" in nft_calls[-1][1]
    assert "tor_ddos4 { 203.0.113.200 timeout 1800s }" in nft_calls[-1][1]
    assert "tor_ddos6 { 2001:db8:bad::1 timeout 1800s }" in nft_calls[-1][1]

    # Duplicate tick within TTL must not emit redundant rule churn
    s2 = nft_ctrl.reconcile("ACTIVE_DOS_PRESSURE", ["203.0.113.200"], now_monotonic=110.0)
    assert s2.added_bans == () and len(nft_calls) == 1

    # Step back to NORMAL after hysteresis -> flush active tor_ddos4/6 cleanly
    s3 = nft_ctrl.reconcile("NORMAL", [], now_monotonic=200.0)
    assert s3.cleared_bans == 2 and s3.active_ban_count == 0
    assert "flush set inet relaysentry_shield tor_ddos4" in nft_calls[-1][1]
    assert "flush set inet relaysentry_shield tor_ddos6" in nft_calls[-1][1]

    # Even if Python active_bans was empty during an attack tick (kernel-added bans), NORMAL recovery flushes sets
    s4 = nft_ctrl.reconcile("ELEVATED_PRESSURE", [], now_monotonic=210.0)
    assert s4.active_ban_count == 0
    s5 = nft_ctrl.reconcile("NORMAL", [], now_monotonic=220.0)
    assert "flush set inet relaysentry_shield tor_ddos4" in nft_calls[-1][1]
    assert "flush set inet relaysentry_shield tor_ddos6" in nft_calls[-1][1]

    # 3. XDP backend controller + atomic failure rollback (state untouched if bpftool fails)
    xdp_calls: list[tuple[list[str], str]] = []
    xdp_ctrl = ShieldController(
        ports={9001},
        consensus_ips=["192.0.2.10"],
        backend="auto",
        dry_run=False,
        ban_ttl_seconds=60,
        command_runner=lambda argv, payload: xdp_calls.append((argv, payload)),
        backend_detector=lambda: "xdp",
    )
    xs1 = xdp_ctrl.reconcile("ELEVATED_PRESSURE", ["203.0.113.250"], now_monotonic=10.0)
    assert xdp_calls[-1][0] == ["bpftool", "batch", "file", "-"]
    assert "blocked_v4 key hex cb 00 71 fa value hex 00 00 00 00 00 00 00 00 any" in xdp_calls[-1][1]
    assert xs1.active_ban_count == 1
    xs2 = xdp_ctrl.reconcile("ELEVATED_PRESSURE", [], now_monotonic=75.0)  # TTL expired
    assert xs2.cleared_bans == 1 and xs2.active_ban_count == 0
    assert "map delete pinned /sys/fs/bpf/relaysentry/blocked_v4 key hex cb 00 71 fa" in xdp_calls[-1][1]

    failing_ctrl = ShieldController(
        ports={9001},
        consensus_ips=["192.0.2.10"],
        backend="auto",
        dry_run=False,
        command_runner=lambda _a, _p: (_ for _ in ()).throw(subprocess.CalledProcessError(1, "nft")),
        backend_detector=lambda: "nft",
    )
    failed = False
    try:
        failing_ctrl.reconcile("ACTIVE_DOS_PRESSURE", ["203.0.113.99"], now_monotonic=50.0)
    except subprocess.CalledProcessError:
        failed = True
    assert failed and failing_ctrl.active_bans == {} and failing_ctrl._last_consensus_sync is None

    # 4. End-to-end CLI --emit-xdp-sync and --enforce-shield --shield-dry-run --json
    with tempfile.TemporaryDirectory(prefix="relaysentry_t10_") as td:
        tmp = Path(td)
        cons_file = tmp / "consensus.json"
        cons_file.write_text(
            json.dumps(
                {
                    "relays": [
                        {
                            "nickname": "DirAuth01",
                            "fingerprint": "A" * 40,
                            "or_addresses": ["192.0.2.10:9001"],
                            "flags": ["Authority", "V2Dir", "Valid", "Running"],
                            "as": "AS64510",
                            "effective_family": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        tcp_file = tmp / "tcp"
        tcp_file.write_text(
            "\n".join(
                [
                    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
                    *[
                        f" {i:3d}: {_encode_ipv4_hex_le('192.0.2.5')}:2329 "
                        f"{_encode_ipv4_hex_le('203.0.113.222')}:{41000 + i:04X} 03 00000000:00000000 00:00000000 0 105 0 {200 + i}"
                        for i in range(30)
                    ],
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        assert cli_main(
            ["--port", "9001", "--consensus-file", str(cons_file), "--offline", "--no-cache", "--emit-xdp-sync"]
        ) == 0
        # Regression checks from Goldfish hostile audits (v0.3.1):
        # (a) --offline --enforce-shield with empty cache/consensus refuses live enforcement (rc=2)
        empty_cache_rc = cli_main(
            ["--port", "9001", "--offline", "--no-cache", "--enforce-shield"]
        )
        assert empty_cache_rc == 2
        # (b) TIME_WAIT (06) sockets excluded from procfs counts, and 2-socket peer stays masked under stride=16
        tw_lines = [
            f" {i:3d}: {_encode_ipv4_hex_le('192.0.2.5')}:2329 "
            f"{_encode_ipv4_hex_le('198.51.100.77')}:{42000 + i:04X} 06 00000000:00000000 00:00000000 0 105 0 {500 + i}"
            for i in range(40)
        ]
        tw_sockets, _ = parse_proc_net_tcp_lines_bounded(tw_lines, {9001})
        assert tw_sockets == [], "TIME_WAIT sockets must not trigger flood attribution"
        # (c) Prometheus float overflow ('1e400') handled without crashing
        inf_snap = parse_prometheus_metrics('tor_relay_connections_total{type="or",state="opened"} 1e400\n')
        assert inf_snap.connections_opened == 0
        # (d) --enforce-shield --shield-dry-run without --reveal-flooders keeps added_bans masked in stdout/JSON
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc_dry = cli_main(
                [
                    "--port",
                    "9001",
                    "--consensus-file",
                    str(cons_file),
                    "--proc-tcp-file",
                    str(tcp_file),
                    "--offline",
                    "--no-cache",
                    "--enforce-shield",
                    "--shield-dry-run",
                    "--allow-cidr",
                    "198.51.100.0/24",
                    "--json",
                ]
            )
        assert rc_dry == 0
        parsed_dry = json.loads(buf.getvalue())
        assert parsed_dry["top_nonrelay_peers"][0]["masked"] is True
        assert all(b.startswith("anon#") for b in parsed_dry["shield_enforcement"]["added_bans"])
        assert "203.0.113.222" not in buf.getvalue()

    print("  [PASS] Built-in ShieldController (nft/XDP), --emit-xdp-sync & dry-run CLI verified.")


def main() -> int:
    print("=" * 74)
    print(" RELAYSENTRY PRIVACY, SPECIFICATION & SANDBOX VERIFICATION SUITE")
    print("=" * 74)
    test_procfs_decoding()
    test_privacy_vault_invariants()
    test_consensus_attribution_and_cluster_rollup()
    test_loopback_metricsport_and_controlport()
    test_cache_permissions_and_cli_json()
    test_cache_ttl_gzip_multiorconn_and_interrupt()
    test_security_hardening_boundaries()
    test_adaptive_shield_xdp_entropy_and_stride()
    test_thunderstorm_and_unresponsive_metrics_resilience()
    test_builtin_shield_controller_and_xdp_sync()
    print("=" * 74)
    print(" ALL 10 RELAYSENTRY BENCHMARK & PRIVACY SUITES PASSED (0 FAILURES)")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
