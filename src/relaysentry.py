#!/usr/bin/env python3
"""RelaySentry: Privacy-Preserving Tor Relay DoS Triage & Peer Attribution CLI."""

import argparse
import http.client
import json
import subprocess
import sys
import time
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from consensus_index import ConsensusIndex, load_consensus_index
from correlator import TriageReport, correlate_triage
from privacy_vault import EphemeralPrivacyVault
from shield_engine import (
    DefenseStateMachine,
    ShieldController,
    ShieldEnforcementSummary,
    TelemetryRingBuffer,
    generate_nft_consensus_sync,
    generate_xdp_map_sync,
    render_xdp_shield_c,
)
from telemetry_procfs import (
    DEFAULT_MAX_EXACT_SOCKETS,
    parse_proc_net_tcp_lines_bounded,
    read_live_procfs_sockets_bounded,
)
from telemetry_tor import (
    TorMetricsSnapshot,
    fetch_metrics_port,
    query_control_orconn,
)


def _validate_ports(raw_ports: list[int]) -> set[int]:
    ports = set()
    for p in raw_ports:
        if not (1 <= p <= 65535):
            raise ValueError(f"Invalid TCP port: {p}")
        ports.add(p)
    return ports


def _report_to_dict(
    report: TriageReport,
    shield_status: ShieldEnforcementSummary | None = None,
) -> dict:
    """Serialize report safely (non-consensus peers use masked tokens unless revealed above threshold)."""
    data = {
        "severity": report.severity,
        "effective_severity": report.effective_severity,
        "cooldown_remaining_seconds": report.cooldown_remaining_seconds,
        "flood_shape": report.flood_shape,
        "nonrelay_entropy_bits": report.nonrelay_entropy_bits,
        "sample_stride": report.sample_stride,
        "metrics_unresponsive": report.metrics_unresponsive,
        "control_unresponsive": report.control_unresponsive,
        "reasons": list(report.reasons),
        "totals": {
            "monitored_sockets": report.total_monitored_sockets,
            "consensus_relay_sockets": report.consensus_socket_total,
            "non_relay_sockets": report.nonrelay_socket_total,
            "syn_recv": report.total_syn_recv,
            "kernel_queue_bytes": report.total_queue_bytes,
        },
        "metrics_delta": (
            {
                "onionskins_processed_delta": report.metrics_delta.onionskins_processed_delta,
                "onionskins_dropped_delta": report.metrics_delta.onionskins_dropped_delta,
                "drop_ratio_pct": round(report.metrics_delta.drop_ratio_pct, 2),
                "oom_bytes_delta": report.metrics_delta.oom_bytes_delta,
                "tcp_exhaustion_delta": report.metrics_delta.tcp_exhaustion_delta,
                "rate_limit_delta": report.metrics_delta.rate_limit_delta,
                "connections_opened": report.metrics_delta.connections_opened,
                "socket_total": report.metrics_delta.socket_total,
                "begindir_rejected_delta": report.metrics_delta.begindir_rejected_delta,
                "circuit_killed_delta": report.metrics_delta.circuit_killed_delta,
                "conn_rejected_delta": report.metrics_delta.conn_rejected_delta,
                "begindir_streams_delta": report.metrics_delta.begindir_streams_delta,
            }
            if report.metrics_delta
            else None
        ),
        "top_consensus_relays": [
            {
                "fingerprint": r.fingerprint,
                "nickname": r.nickname,
                "flags": list(r.flags),
                "as": r.as_number,
                "as_name": r.as_name,
                "subnet24": r.primary_ipv4_24,
                "family_cluster": r.family_group_id,
                "family_size": r.family_size,
                "overloaded": r.overloaded,
                "orconn_state": r.orconn_state,
                "sockets": r.stats.total_sockets,
                "established": r.stats.established,
                "syn_recv": r.stats.syn_recv,
                "queue_bytes": r.stats.rx_queue_bytes + r.stats.tx_queue_bytes,
            }
            for r in report.consensus_peers[:20]
        ],
        "cluster_rollups": [
            {
                "cluster_key": c.cluster_key,
                "kind": c.cluster_kind,
                "relay_count": c.relay_count,
                "total_sockets": c.total_sockets,
                "syn_recv": c.syn_recv,
                "queue_bytes": c.queue_bytes,
                "as_numbers": list(c.as_numbers),
                "nicknames": list(c.nicknames),
            }
            for c in report.cluster_rollups[:15]
        ],
        "top_nonrelay_peers": [
            {
                "peer": p.label,
                "masked": p.masked,
                "sockets": p.stats.total_sockets,
                "established": p.stats.established,
                "syn_recv": p.stats.syn_recv,
                "queue_bytes": p.stats.rx_queue_bytes + p.stats.tx_queue_bytes,
            }
            for p in report.nonrelay_peers[:20]
        ],
        "nft_hints": list(report.nft_hints),
        "tor_defense_hints": list(report.tor_defense_hints),
    }
    if shield_status is not None:
        data["shield_enforcement"] = shield_status.to_dict()
    return data


def format_terminal_report(
    report: TriageReport,
    top_n: int = 10,
    shield_status: ShieldEnforcementSummary | None = None,
) -> str:
    """Format a clean human-readable triage report for terminal display."""
    lines: list[str] = []
    ts_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    hold_note = (
        f" (HYSTERESIS HOLD {report.cooldown_remaining_seconds:.0f}s, raw={report.severity})"
        if report.effective_severity != report.severity
        else ""
    )
    stride_note = f" | Stride: 1-in-{report.sample_stride}" if report.sample_stride > 1 else ""
    lines.append("=" * 78)
    lines.append(
        f" RELAYSENTRY [{ts_utc}]  |  STATUS: {report.effective_severity}{hold_note}\n"
        f" SOCKETS: {report.total_monitored_sockets} "
        f"(Consensus: {report.consensus_socket_total}, Non-Relay: {report.nonrelay_socket_total}) "
        f"| SYN_RECV: {report.total_syn_recv} | Queue: {report.total_queue_bytes} bytes\n"
        f" SHAPE: {report.flood_shape} (entropy={report.nonrelay_entropy_bits:.2f}b){stride_note}"
    )
    if report.reasons:
        lines.append(" SIGNALS: " + " ; ".join(report.reasons))
    if report.metrics_delta:
        d = report.metrics_delta
        lines.append(
            f" METRICSPORT: opened={d.connections_opened}, sock_tot={d.socket_total}, "
            f"ntor_dropped={d.onionskins_dropped_delta} ({d.drop_ratio_pct:.1f}%), "
            f"begindir_rej={d.begindir_rejected_delta}, ckt_kill={d.circuit_killed_delta}, "
            f"oom_bytes={d.oom_bytes_delta}, tcp_exhaust={d.tcp_exhaustion_delta}"
        )
    if report.metrics_unresponsive or report.control_unresponsive:
        stalled = [
            name
            for name, flag in (
                ("MetricsPort", report.metrics_unresponsive),
                ("ControlPort", report.control_unresponsive),
            )
            if flag
        ]
        lines.append(f" TELEMETRY_STALL: {', '.join(stalled)} timed out/refused (continuing procfs triage)")
    if shield_status is not None:
        mode = f"{shield_status.backend}:DRY-RUN" if shield_status.dry_run else shield_status.backend.upper()
        bans_note = ",".join(shield_status.added_bans[:5]) if shield_status.added_bans else "none"
        lines.append(
            f" SHIELD [{mode}]: active_bans={shield_status.active_ban_count} "
            f"| added=({bans_note}) | cleared={shield_status.cleared_bans} "
            f"| consensus_sync={shield_status.consensus_synced} | protected_skip={shield_status.skipped_protected}"
        )
    lines.append("=" * 78)

    if report.cluster_rollups:
        lines.append("\n[1] CONSENSUS RELAY CLUSTERS (by effective_family or AS+/24)")
        for c in report.cluster_rollups[:top_n]:
            nicks = ", ".join(c.nicknames)
            lines.append(
                f"  - {c.cluster_key:<26} ({c.cluster_kind}) | relays={c.relay_count} "
                f"| sock={c.total_sockets} syn={c.syn_recv} q={c.queue_bytes}B | [{nicks}]"
            )

    if report.consensus_peers:
        lines.append("\n[2] TOP CONSENSUS RELAYS HITTING MONITORED PORTS")
        for r in report.consensus_peers[:top_n]:
            flags = ",".join(r.flags[:4]) if r.flags else "none"
            orconn = f" ORCONN={r.orconn_state}" if r.orconn_state else ""
            lines.append(
                f"  - {r.nickname:<16} (${r.fingerprint[:12]}.. {r.as_number}) "
                f"[{flags}]{orconn} | sock={r.stats.total_sockets} "
                f"(EST={r.stats.established}, SYN={r.stats.syn_recv}, Q={r.stats.rx_queue_bytes + r.stats.tx_queue_bytes}B)"
            )

    if report.nonrelay_peers:
        lines.append("\n[3] TOP NON-RELAY PEERS (Strict Ephemeral HMAC Privacy)")
        for p in report.nonrelay_peers[:top_n]:
            tag = "MASKED" if p.masked else "REVEALED_FLOODER"
            lines.append(
                f"  - {p.label:<24} [{tag}] | sock={p.stats.total_sockets} "
                f"(EST={p.stats.established}, SYN={p.stats.syn_recv}, Q={p.stats.rx_queue_bytes + p.stats.tx_queue_bytes}B)"
            )

    if report.nft_hints:
        lines.append("\n[4] CANDIDATE OPERATOR NFTABLES SHIELD RULES (Manual Review Only)")
        for hint in report.nft_hints[: top_n * 2]:
            lines.append(f"  {hint}")

    if report.tor_defense_hints:
        lines.append("\n[5] ADAPTIVE TOR & KERNEL DEFENSE GUIDANCE")
        for g in report.tor_defense_hints:
            lines.append(f"  * {g}")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="relaysentry",
        description="Privacy-preserving Tor relay DoS triage & consensus peer attribution CLI.",
    )
    p.add_argument(
        "--port",
        type=int,
        action="append",
        required=True,
        help="Monitored local ORPort or DirPort TCP port (repeatable, e.g. --port 9001 --port 9030)",
    )
    p.add_argument("--metrics-url", help="Local Tor MetricsPort HTTP URL (e.g. http://127.0.0.1:9035/metrics)")
    p.add_argument("--control-host", default="127.0.0.1", help="Tor ControlPort host (default: 127.0.0.1)")
    p.add_argument("--control-port", type=int, help="Tor ControlPort TCP port (e.g. 9051)")
    p.add_argument("--control-cookie", type=Path, help="Path to Tor 32-byte control_auth_cookie")
    p.add_argument("--consensus-file", type=Path, help="Path to local Onionoo details JSON file")
    p.add_argument("--proc-tcp-file", type=Path, help="Optional fixture /proc/net/tcp file for offline replay")
    p.add_argument("--proc-tcp6-file", type=Path, help="Optional fixture /proc/net/tcp6 file for offline replay")
    p.add_argument("--no-cache", action="store_true", help="Do not write Onionoo cache files to disk (RAM-only)")
    p.add_argument("--refresh", action="store_true", help="Force refresh Onionoo consensus even if cache is fresh")
    p.add_argument("--offline", action="store_true", help="Do not fetch Onionoo over network")
    p.add_argument("--proxy", help="HTTP/HTTPS proxy URL for Onionoo directory fetches")
    p.add_argument(
        "--reveal-flooders",
        action="store_true",
        help="In live RAM only, unmask non-relay peers holding >= --flood-threshold sockets (never persisted)",
    )
    p.add_argument(
        "--flood-threshold",
        type=int,
        default=25,
        help="Minimum concurrent sockets before a peer triggers flood attribution/reveal (default: 25)",
    )
    p.add_argument(
        "--emit-nft-hints",
        action="store_true",
        help="Print suggested nftables notrack/rate-limit commands for revealed non-relay flooders (requires --reveal-flooders)",
    )
    p.add_argument(
        "--emit-xdp-c",
        action="store_true",
        help="Emit dual-stack XDP/eBPF C shield source tailored to --port (consensus allowlist + O(1) SYN token bucket)",
    )
    p.add_argument(
        "--emit-nft-consensus",
        action="store_true",
        help="Emit atomic nftables consensus allowlist (known_relays4/6) + non-relay DoS rate-limit script tailored to --port",
    )
    p.add_argument(
        "--emit-xdp-sync",
        action="store_true",
        help="Emit bpftool batch script populating allow_relay_v4/6 (and blocked_v4/6 if enabled) from Consensus",
    )
    p.add_argument(
        "--enforce-shield",
        action="store_true",
        help="Enable built-in adaptive kernel shield enforcement (nftables or XDP; Consensus & honest clients stay exempt)",
    )
    p.add_argument(
        "--shield-backend",
        choices=("auto", "nft", "xdp"),
        default="auto",
        help="Kernel enforcement backend for --enforce-shield (default: auto)",
    )
    p.add_argument(
        "--shield-dry-run",
        action="store_true",
        help="Validate and report --enforce-shield consensus sync and flooder bans without modifying kernel rules",
    )
    p.add_argument(
        "--ban-ttl",
        type=int,
        default=1800,
        help="Auto-expiry TTL in seconds for active non-relay flooder blocks under --enforce-shield (default: 1800)",
    )
    p.add_argument(
        "--bpf-pin-dir",
        default="/sys/fs/bpf/relaysentry",
        help="bpffs pin directory holding relaysentry XDP maps (default: /sys/fs/bpf/relaysentry)",
    )
    p.add_argument(
        "--allow-cidr",
        action="append",
        default=[],
        help="Protected IP/CIDR that --enforce-shield must never block on monitored ports (repeatable)",
    )
    p.add_argument(
        "--hysteresis-seconds",
        type=float,
        default=60.0,
        help="Minimum hold window (seconds) before de-escalating peak alert state during pulsing attacks (default: 60)",
    )
    p.add_argument(
        "--max-exact-sockets",
        type=int,
        default=DEFAULT_MAX_EXACT_SOCKETS,
        help="Engage 1-in-16 overload stride sampling above this many monitored sockets (0 = disable, default: 50000)",
    )
    p.add_argument(
        "--metrics-timeout",
        type=float,
        default=5.0,
        help="Timeout in seconds for MetricsPort/ControlPort scrapes before marking stalled (default: 5.0)",
    )
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    p.add_argument("--watch", type=float, default=0.0, help="Refresh interval in seconds (0 = single snapshot)")
    return p


MAX_PROCFS_FILE_BYTES = 64 * 1024 * 1024


def _iter_bounded_procfs_lines(paths: list[Path]):
    """Yield lines from procfs fixture files cleanly within strict byte cap (CWE-400)."""
    total = 0
    for path in paths:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                total += len(line.encode("utf-8", errors="replace"))
                if total > MAX_PROCFS_FILE_BYTES:
                    raise ValueError(f"Procfs fixture exceeds 64 MiB safety bound: {path}")
                yield line


def _read_bounded_procfs_fixture(path: Path, ports: set[int]) -> list:
    """Stream /proc/net/tcp fixture file cleanly within strict byte cap (CWE-400)."""
    sockets, _ = parse_proc_net_tcp_lines_bounded(
        _iter_bounded_procfs_lines([path]),
        ports,
        max_exact_sockets=0,
    )
    return sockets


def run_once(
    ports: set[int],
    consensus: ConsensusIndex,
    vault: EphemeralPrivacyVault,
    args: argparse.Namespace,
    prev_metrics: TorMetricsSnapshot | None,
    state_machine: DefenseStateMachine | None = None,
    ring_buffer: TelemetryRingBuffer | None = None,
    shield_controller: ShieldController | None = None,
) -> tuple[TriageReport, TorMetricsSnapshot | None]:
    max_exact = getattr(args, "max_exact_sockets", DEFAULT_MAX_EXACT_SOCKETS)
    fixture_paths = [p for p in (args.proc_tcp_file, args.proc_tcp6_file) if p]
    if fixture_paths:
        sockets, sample_stride = parse_proc_net_tcp_lines_bounded(
            _iter_bounded_procfs_lines(fixture_paths),
            ports,
            max_exact_sockets=max_exact,
        )
    else:
        sockets, sample_stride = read_live_procfs_sockets_bounded(
            ports,
            max_exact_sockets=max_exact,
        )

    telemetry_timeout = float(getattr(args, "metrics_timeout", 5.0))
    metrics_unresponsive = False
    curr_metrics: TorMetricsSnapshot | None = None
    if args.metrics_url:
        try:
            curr_metrics = fetch_metrics_port(args.metrics_url, timeout=telemetry_timeout)
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
            metrics_unresponsive = True
            print(
                f"[WARN] MetricsPort unresponsive ({exc.__class__.__name__}: {exc}); continuing procfs triage",
                file=sys.stderr,
            )

    control_unresponsive = False
    orconns = None
    if args.control_port:
        try:
            orconns = query_control_orconn(
                host=args.control_host,
                port=args.control_port,
                cookie_path=args.control_cookie,
                timeout=telemetry_timeout,
            )
        except (TimeoutError, OSError) as exc:
            if isinstance(exc, PermissionError) and "EOF" not in str(exc):
                raise
            control_unresponsive = True
            print(
                f"[WARN] ControlPort unresponsive ({exc.__class__.__name__}: {exc}); continuing procfs triage",
                file=sys.stderr,
            )

    report = correlate_triage(
        sockets=sockets,
        consensus=consensus,
        vault=vault,
        metrics_curr=curr_metrics,
        metrics_prev=prev_metrics,
        orconns=orconns,
        flood_threshold=args.flood_threshold,
        emit_nft_hints=args.emit_nft_hints,
        sample_stride=sample_stride,
        state_machine=state_machine,
        ring_buffer=ring_buffer,
        metrics_unresponsive=metrics_unresponsive,
        control_unresponsive=control_unresponsive,
    )
    if shield_controller is not None:
        candidate_ips = [p.label for p in report.nonrelay_peers if not p.masked]
        try:
            shield_controller.reconcile(report.effective_severity, candidate_ips)
        except (subprocess.SubprocessError, OSError) as exc:
            print(
                f"[WARN] Built-in shield update failed ({exc.__class__.__name__}: {exc}); continuing monitoring",
                file=sys.stderr,
            )
    next_prev_metrics = curr_metrics if curr_metrics is not None else prev_metrics
    return report, next_prev_metrics


def _safe_stdout(text: str) -> bool:
    """Write output cleanly, suppressing BrokenPipeError when piped to head/grep."""
    try:
        print(text, flush=True)
        return True
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except OSError:
            pass
        return False


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.watch < 0:
        raise ValueError("--watch interval must be >= 0")
    if args.hysteresis_seconds < 0:
        raise ValueError("--hysteresis-seconds must be >= 0")
    if args.max_exact_sockets < 0:
        raise ValueError("--max-exact-sockets must be >= 0")
    if args.metrics_timeout <= 0:
        raise ValueError("--metrics-timeout must be > 0")
    if args.ban_ttl <= 0:
        raise ValueError("--ban-ttl must be > 0")

    ports = _validate_ports(args.port)
    if args.emit_xdp_c:
        _safe_stdout(render_xdp_shield_c(ports))
        return 0

    if args.emit_nft_hints and not args.reveal_flooders:
        print(
            "[NOTE] --emit-nft-hints only emits rules for unmasked flooders above "
            "--flood-threshold; pass --reveal-flooders alongside it if you want nft hints.",
            file=sys.stderr,
        )
    if args.enforce_shield:
        print(
            f"[SHIELD] Built-in shield enabled (backend={args.shield_backend}, dry_run={args.shield_dry_run}, "
            f"ban_ttl={args.ban_ttl}s); peers < {args.flood_threshold} sockets remain masked & consensus relays stay exempt.",
            file=sys.stderr,
        )
    vault = EphemeralPrivacyVault(
        reveal_flooders=bool(args.reveal_flooders or args.enforce_shield),
        flood_threshold=args.flood_threshold,
    )
    consensus = load_consensus_index(
        consensus_file=args.consensus_file,
        no_cache=args.no_cache,
        offline=args.offline,
        proxy_url=args.proxy,
        refresh=args.refresh,
    )
    if args.emit_nft_consensus:
        _safe_stdout(
            generate_nft_consensus_sync(
                consensus.ip_to_fps.keys(),
                ports,
                conn_limit=args.flood_threshold,
                ban_timeout=f"{args.ban_ttl}s",
            )
        )
        return 0
    if args.emit_xdp_sync:
        _safe_stdout(
            generate_xdp_map_sync(
                consensus.ip_to_fps.keys(),
                pin_dir=args.bpf_pin_dir,
            )
        )
        return 0

    shield_controller: ShieldController | None = None
    if args.enforce_shield:
        shield_controller = ShieldController(
            ports=ports,
            consensus_ips=consensus.ip_to_fps.keys(),
            backend=args.shield_backend,
            dry_run=args.shield_dry_run,
            ban_ttl_seconds=args.ban_ttl,
            flood_threshold=args.flood_threshold,
            bpf_pin_dir=args.bpf_pin_dir,
            allow_cidrs=args.allow_cidr,
        )

    state_machine = DefenseStateMachine(hold_seconds=args.hysteresis_seconds)
    ring_buffer = TelemetryRingBuffer(maxlen=64)
    prev_metrics: TorMetricsSnapshot | None = None
    try:
        while True:
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
            shield_summary = shield_controller.last_summary if shield_controller is not None else None
            out_text = (
                json.dumps(_report_to_dict(report, shield_status=shield_summary), indent=2)
                if args.json
                else format_terminal_report(report, shield_status=shield_summary)
            )
            if not _safe_stdout(out_text):
                return 0
            if args.watch <= 0:
                break
            time.sleep(args.watch)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
