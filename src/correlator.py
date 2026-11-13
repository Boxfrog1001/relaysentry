"""Multi-signal Tor relay DoS triage & consensus peer correlator."""

import hashlib
import time
from dataclasses import dataclass, field

from consensus_index import ConsensusIndex, RelayMeta
from privacy_vault import EphemeralPrivacyVault
from shield_engine import (
    DefenseStateMachine,
    ShieldWindowSample,
    TelemetryRingBuffer,
    classify_flood_shape,
    generate_kernel_nft_rules,
    generate_tor_defense_hints,
)
from telemetry_procfs import SocketEntry
from telemetry_tor import OrConnEntry, TorMetricsSnapshot


@dataclass
class PeerAggregate:
    """Aggregated socket telemetry for a single remote peer IP."""

    total_sockets: int = 0
    established: int = 0
    syn_recv: int = 0
    close_wait: int = 0
    other_states: int = 0
    rx_queue_bytes: int = 0
    tx_queue_bytes: int = 0
    ports_hit: set[int] = field(default_factory=set)

    def add_socket(self, sock: SocketEntry) -> None:
        self.total_sockets += 1
        self.ports_hit.add(sock.local_port)
        self.rx_queue_bytes += sock.rx_queue
        self.tx_queue_bytes += sock.tx_queue
        if sock.state == "ESTABLISHED":
            self.established += 1
        elif sock.state in ("SYN_RECV", "NEW_SYN_RECV"):
            self.syn_recv += 1
        elif sock.state == "CLOSE_WAIT":
            self.close_wait += 1
        else:
            self.other_states += 1


@dataclass(frozen=True)
class RelayAttribution:
    """Confirmed public consensus relay contributing active OR/Dir traffic."""

    fingerprint: str
    nickname: str
    flags: tuple[str, ...]
    as_number: str
    as_name: str
    primary_ipv4_24: str
    family_group_id: str
    family_size: int
    version: str
    overloaded: bool
    stats: PeerAggregate
    orconn_state: str | None = None


@dataclass(frozen=True)
class ClusterRollup:
    """Grouped consensus traffic by effective_family (or shared AS + /24 subnet)."""

    cluster_key: str
    cluster_kind: str
    relay_count: int
    total_sockets: int
    syn_recv: int
    queue_bytes: int
    as_numbers: tuple[str, ...]
    nicknames: tuple[str, ...]


@dataclass(frozen=True)
class NonRelayPeerReport:
    """Privacy-preserving telemetry record for non-consensus peer IPs."""

    label: str
    token: str
    masked: bool
    stats: PeerAggregate


@dataclass(frozen=True)
class MetricsDelta:
    """Per-interval Tor MetricsPort deltas."""

    onionskins_processed_delta: int
    onionskins_dropped_delta: int
    drop_ratio_pct: float
    oom_bytes_delta: int
    tcp_exhaustion_delta: int
    rate_limit_delta: int
    connections_opened: int
    socket_total: int
    begindir_rejected_delta: int = 0
    circuit_killed_delta: int = 0
    conn_rejected_delta: int = 0
    begindir_streams_delta: int = 0


@dataclass(frozen=True)
class TriageReport:
    """Complete point-in-time DoS attribution & health report."""

    severity: str
    reasons: tuple[str, ...]
    total_monitored_sockets: int
    consensus_socket_total: int
    nonrelay_socket_total: int
    total_syn_recv: int
    total_queue_bytes: int
    consensus_peers: tuple[RelayAttribution, ...]
    cluster_rollups: tuple[ClusterRollup, ...]
    nonrelay_peers: tuple[NonRelayPeerReport, ...]
    metrics_snapshot: TorMetricsSnapshot | None
    metrics_delta: MetricsDelta | None
    nft_hints: tuple[str, ...]
    effective_severity: str = "NORMAL"
    cooldown_remaining_seconds: float = 0.0
    flood_shape: str = "IDLE"
    nonrelay_entropy_bits: float = 0.0
    sample_stride: int = 1
    tor_defense_hints: tuple[str, ...] = ()
    metrics_unresponsive: bool = False
    control_unresponsive: bool = False
    heavy_nonrelay_ips: tuple[str, ...] = ()


def _family_cluster_key(meta: RelayMeta) -> tuple[str, str]:
    """Compute canonical cluster ID from effective_family or AS+/24 fallback."""
    if meta.effective_family:
        members = sorted({meta.fingerprint, *meta.effective_family})
        digest = hashlib.sha256(",".join(members).encode("ascii")).hexdigest()[:10]
        return f"family#{digest}", "effective_family"
    return f"{meta.as_number}:{meta.primary_ipv4_24}", "asn_subnet24"


def _stride_eligible_count(raw_sockets: int, stride: int, flood_threshold: int) -> int:
    """Scale sampled socket count only after meeting the anti-noise raw sample floor."""
    est = raw_sockets * stride
    if stride == 1:
        return est
    # Under 1-in-N overload sampling, require >= 3 raw samples so 1-2 socket clients never reveal/ban/alert.
    min_stride_samples = max(3, (flood_threshold // stride) + 1)
    return est if raw_sockets >= min_stride_samples else 0


def compute_metrics_delta(
    current: TorMetricsSnapshot | None,
    previous: TorMetricsSnapshot | None,
) -> MetricsDelta | None:
    """Compute non-negative counter deltas between two MetricsPort scrapes."""
    if current is None:
        return None
    if previous is None:
        return MetricsDelta(
            onionskins_processed_delta=current.total_onionskins_processed,
            onionskins_dropped_delta=current.total_onionskins_dropped,
            drop_ratio_pct=current.drop_ratio_pct,
            oom_bytes_delta=current.oom_bytes_total,
            tcp_exhaustion_delta=current.tcp_exhaustion_total,
            rate_limit_delta=current.global_rate_limit_total,
            connections_opened=current.connections_opened,
            socket_total=current.socket_total,
            begindir_rejected_delta=current.total_begindir_rejected,
            circuit_killed_delta=current.circuit_killed_max_cell,
            conn_rejected_delta=current.conn_rejected,
            begindir_streams_delta=current.begindir_streams_total,
        )
    proc_d = max(0, current.total_onionskins_processed - previous.total_onionskins_processed)
    drop_d = max(0, current.total_onionskins_dropped - previous.total_onionskins_dropped)
    denom = proc_d + drop_d
    ratio = (drop_d / denom * 100.0) if denom > 0 else 0.0
    return MetricsDelta(
        onionskins_processed_delta=proc_d,
        onionskins_dropped_delta=drop_d,
        drop_ratio_pct=ratio,
        oom_bytes_delta=max(0, current.oom_bytes_total - previous.oom_bytes_total),
        tcp_exhaustion_delta=max(0, current.tcp_exhaustion_total - previous.tcp_exhaustion_total),
        rate_limit_delta=max(0, current.global_rate_limit_total - previous.global_rate_limit_total),
        connections_opened=current.connections_opened,
        socket_total=current.socket_total,
        begindir_rejected_delta=max(0, current.total_begindir_rejected - previous.total_begindir_rejected),
        circuit_killed_delta=max(0, current.circuit_killed_max_cell - previous.circuit_killed_max_cell),
        conn_rejected_delta=max(0, current.conn_rejected - previous.conn_rejected),
        begindir_streams_delta=max(0, current.begindir_streams_total - previous.begindir_streams_total),
    )


def correlate_triage(
    sockets: list[SocketEntry],
    consensus: ConsensusIndex,
    vault: EphemeralPrivacyVault,
    metrics_curr: TorMetricsSnapshot | None = None,
    metrics_prev: TorMetricsSnapshot | None = None,
    orconns: list[OrConnEntry] | None = None,
    flood_threshold: int = 25,
    emit_nft_hints: bool = False,
    sample_stride: int = 1,
    state_machine: DefenseStateMachine | None = None,
    ring_buffer: TelemetryRingBuffer | None = None,
    metrics_unresponsive: bool = False,
    control_unresponsive: bool = False,
) -> TriageReport:
    """Correlate socket floods, consensus relays, families, entropy, hysteresis & Tor metrics."""
    stride = max(1, int(sample_stride))
    by_ip: dict[str, PeerAggregate] = {}
    for sock in sockets:
        agg = by_ip.setdefault(sock.remote_ip, PeerAggregate())
        agg.add_socket(sock)

    orconn_by_fp = {entry.fingerprint: entry.status for entry in (orconns or [])}

    consensus_peers: list[RelayAttribution] = []
    nonrelay_peers: list[NonRelayPeerReport] = []
    cluster_buckets: dict[tuple[str, str], list[RelayAttribution]] = {}
    disclosed_flooders: list[tuple[str, tuple[int, ...]]] = []
    heavy_nonrelay_ips: list[str] = []

    consensus_sockets = 0
    nonrelay_sockets = 0
    total_syn_recv = 0
    total_queue_bytes = 0

    for remote_ip, agg in by_ip.items():
        total_syn_recv += agg.syn_recv * stride
        total_queue_bytes += (agg.rx_queue_bytes + agg.tx_queue_bytes) * stride
        relays = consensus.lookup_ip(remote_ip)
        if relays:
            consensus_sockets += agg.total_sockets * stride
            # Select highest-weight descriptor when multi-instance IP hosts relays.
            primary = max(relays, key=lambda r: r.consensus_weight)
            c_key, c_kind = _family_cluster_key(primary)
            orconn_state = next(
                (orconn_by_fp[r.fingerprint] for r in relays if r.fingerprint in orconn_by_fp),
                None,
            )
            attr = RelayAttribution(
                fingerprint=primary.fingerprint,
                nickname=primary.nickname,
                flags=primary.flags,
                as_number=primary.as_number,
                as_name=primary.as_name,
                primary_ipv4_24=primary.primary_ipv4_24,
                family_group_id=c_key,
                family_size=len(primary.effective_family) + 1,
                version=primary.version,
                overloaded=primary.overloaded,
                stats=agg,
                orconn_state=orconn_state,
            )
            consensus_peers.append(attr)
            cluster_buckets.setdefault((c_key, c_kind), []).append(attr)
        else:
            est_nonrelay = agg.total_sockets * stride
            nonrelay_sockets += est_nonrelay
            threshold_count = _stride_eligible_count(agg.total_sockets, stride, flood_threshold)
            if threshold_count >= flood_threshold:
                heavy_nonrelay_ips.append(remote_ip)
            peer_label = vault.classify_nonrelay(remote_ip, threshold_count)
            display = peer_label.disclosed_ip if peer_label.disclosed_ip else peer_label.token
            nonrelay_peers.append(
                NonRelayPeerReport(
                    label=display,
                    token=peer_label.token,
                    masked=peer_label.masked,
                    stats=agg,
                )
            )
            if emit_nft_hints and not peer_label.masked and peer_label.disclosed_ip:
                disclosed_flooders.append((peer_label.disclosed_ip, tuple(sorted(agg.ports_hit))))

    nft_hints = generate_kernel_nft_rules(disclosed_flooders) if emit_nft_hints else []

    consensus_peers.sort(
        key=lambda r: (r.stats.total_sockets, r.stats.syn_recv, r.stats.rx_queue_bytes + r.stats.tx_queue_bytes),
        reverse=True,
    )
    nonrelay_peers.sort(
        key=lambda p: (p.stats.total_sockets, p.stats.syn_recv, p.stats.rx_queue_bytes + p.stats.tx_queue_bytes),
        reverse=True,
    )

    cluster_rollups: list[ClusterRollup] = []
    for (c_key, c_kind), members in cluster_buckets.items():
        cluster_rollups.append(
            ClusterRollup(
                cluster_key=c_key,
                cluster_kind=c_kind,
                relay_count=len(members),
                total_sockets=sum(m.stats.total_sockets * stride for m in members),
                syn_recv=sum(m.stats.syn_recv * stride for m in members),
                queue_bytes=sum((m.stats.rx_queue_bytes + m.stats.tx_queue_bytes) * stride for m in members),
                as_numbers=tuple(sorted({m.as_number for m in members})),
                nicknames=tuple(m.nickname for m in members[:6]),
            )
        )
    cluster_rollups.sort(key=lambda c: (c.total_sockets, c.queue_bytes), reverse=True)

    delta = compute_metrics_delta(metrics_curr, metrics_prev)
    reasons: list[str] = []

    if total_syn_recv >= flood_threshold:
        reasons.append(f"HIGH_SYN_RECV_BACKLOG ({total_syn_recv} half-open sockets)")
    heavy_relays = [
        r
        for r in consensus_peers
        if _stride_eligible_count(r.stats.total_sockets, stride, flood_threshold) >= flood_threshold
    ]
    if heavy_relays:
        reasons.append(f"HEAVY_CONSENSUS_RELAY_PEERS ({len(heavy_relays)} relays >= {flood_threshold} sockets)")
    heavy_nonrelays = [
        p
        for p in nonrelay_peers
        if _stride_eligible_count(p.stats.total_sockets, stride, flood_threshold) >= flood_threshold
    ]
    if heavy_nonrelays:
        reasons.append(f"NONRELAY_PEER_FLOOD ({len(heavy_nonrelays)} peers >= {flood_threshold} sockets)")
    heavy_clusters = [c for c in cluster_rollups if c.total_sockets >= flood_threshold * 2]
    if heavy_clusters:
        reasons.append(f"CONCENTRATED_RELAY_CLUSTER ({heavy_clusters[0].cluster_key}: {heavy_clusters[0].total_sockets} sockets)")
    if total_queue_bytes >= 1024 * 1024:
        reasons.append(f"KERNEL_SOCKET_QUEUE_BACKPRESSURE ({total_queue_bytes} bytes)")

    relay_queue_bytes = sum((r.stats.rx_queue_bytes + r.stats.tx_queue_bytes) * stride for r in consensus_peers)

    if metrics_unresponsive:
        reasons.append("METRICS_PORT_UNRESPONSIVE (MetricsPort timed out or refused; Tor event loop may be saturated)")
    if control_unresponsive:
        reasons.append("CONTROL_PORT_UNRESPONSIVE (ControlPort ORCONN query timed out or refused)")

    if delta is not None:
        if delta.onionskins_dropped_delta > 0 and delta.drop_ratio_pct >= 5.0:
            reasons.append(
                f"ONIONSKIN_DROPS ({delta.onionskins_dropped_delta} dropped, {delta.drop_ratio_pct:.1f}%)"
            )
        if delta.oom_bytes_delta > 0:
            reasons.append(f"TOR_OOM_TRIGGERED ({delta.oom_bytes_delta} bytes freed)")
        if delta.tcp_exhaustion_delta > 0:
            reasons.append(f"TCP_PORT_EXHAUSTION ({delta.tcp_exhaustion_delta} events)")
        if delta.begindir_rejected_delta >= 50 or (
            delta.begindir_rejected_delta > 0 and (heavy_relays or total_queue_bytes >= 512 * 1024)
        ):
            reasons.append(
                f"THUNDERSTORM_BEGIN_DIR_FLOOD ({delta.begindir_rejected_delta} BEGIN_DIR DoS rejections, "
                f"{delta.begindir_streams_delta} BEGIN_DIR streams)"
            )
        elif delta.begindir_streams_delta >= 500 and (heavy_relays or total_queue_bytes >= 512 * 1024):
            reasons.append(
                f"THUNDERSTORM_BEGIN_DIR_FLOOD ({delta.begindir_streams_delta} BEGIN_DIR streams with relay/queue pressure)"
            )
        if delta.circuit_killed_delta > 0 or delta.conn_rejected_delta >= 25:
            reasons.append(
                f"TOR_CIRCUIT_CELL_DOS_TRIGGERS (circuit_killed={delta.circuit_killed_delta}, "
                f"conn_rejected={delta.conn_rejected_delta})"
            )

    if metrics_unresponsive and (
        heavy_relays or heavy_nonrelays or total_queue_bytes >= 512 * 1024 or total_syn_recv >= flood_threshold
    ):
        reasons.append(
            "HALF_OPEN_BEGIN_DIR_BYPASS_SUSPECTED (MetricsPort stalled alongside active socket/queue pressure)"
        )
    elif (
        delta is not None
        and delta.begindir_rejected_delta == 0
        and heavy_relays
        and (relay_queue_bytes >= 512 * 1024 or total_queue_bytes >= 1024 * 1024)
    ):
        reasons.append(
            f"HALF_OPEN_BEGIN_DIR_BYPASS_SUSPECTED (0 BEGIN_DIR DoS rejections despite {len(heavy_relays)} heavy relays "
            f"and {max(relay_queue_bytes, total_queue_bytes)}B queued)"
        )

    raw_severity = "NORMAL"
    if (
        len(reasons) >= 2
        or (
            delta
            and (
                delta.oom_bytes_delta > 0
                or delta.drop_ratio_pct >= 15.0
                or delta.begindir_rejected_delta >= 100
                or delta.circuit_killed_delta >= 25
            )
        )
        or total_syn_recv >= flood_threshold * 2
        or (
            metrics_unresponsive
            and (
                total_queue_bytes >= 512 * 1024
                or bool(heavy_relays)
                or bool(heavy_nonrelays)
                or total_syn_recv >= flood_threshold
            )
        )
    ):
        raw_severity = "ACTIVE_DOS_PRESSURE"
    elif reasons:
        raw_severity = "ELEVATED_PRESSURE"

    if state_machine is not None:
        effective_severity, cooldown_rem = state_machine.step(raw_severity)
    else:
        effective_severity, cooldown_rem = raw_severity, 0.0

    # Entropy is computed solely over anonymized peer counts (zero raw client IPs read).
    flood_shape, entropy_bits = classify_flood_shape(
        (p.stats.total_sockets for p in nonrelay_peers),
        sum(p.stats.total_sockets for p in nonrelay_peers),
    )
    tor_hints = generate_tor_defense_hints(reasons, flood_shape, effective_severity)

    est_total_monitored = len(sockets) * stride
    if ring_buffer is not None:
        ring_buffer.push(
            ShieldWindowSample(
                timestamp_monotonic=time.monotonic(),
                raw_severity=raw_severity,
                effective_severity=effective_severity,
                total_sockets=est_total_monitored,
                syn_recv=total_syn_recv,
                queue_bytes=total_queue_bytes,
                nonrelay_entropy_bits=round(entropy_bits, 3),
                sample_stride=stride,
            )
        )

    return TriageReport(
        severity=raw_severity,
        reasons=tuple(reasons),
        total_monitored_sockets=est_total_monitored,
        consensus_socket_total=consensus_sockets,
        nonrelay_socket_total=nonrelay_sockets,
        total_syn_recv=total_syn_recv,
        total_queue_bytes=total_queue_bytes,
        consensus_peers=tuple(consensus_peers),
        cluster_rollups=tuple(cluster_rollups),
        nonrelay_peers=tuple(nonrelay_peers),
        metrics_snapshot=metrics_curr,
        metrics_delta=delta,
        nft_hints=tuple(nft_hints),
        effective_severity=effective_severity,
        cooldown_remaining_seconds=round(cooldown_rem, 1),
        flood_shape=flood_shape,
        nonrelay_entropy_bits=round(entropy_bits, 2),
        sample_stride=stride,
        tor_defense_hints=tuple(tor_hints),
        metrics_unresponsive=metrics_unresponsive,
        control_unresponsive=control_unresponsive,
        heavy_nonrelay_ips=tuple(heavy_nonrelay_ips),
    )
