"""
backend/health_matrix.py   
Server-side route analysis.

The nodes themselves run RoutingTable.select_best_next_hop() locally.
This module analyses the *historical packet data* stored in SQLite to:
  1. Reconstruct observed paths and cost them.
  2. Recommend the best end-to-end route from any source → GATEWAY.
  3. Detect route flapping / instability.

Cost formula (mirrors routing_table.py so results are comparable):
    cost = avg_latency_ms + (power_cost * 10)

Power costs per protocol (lower = cheaper):
    BLE  = 0.5
    WiFi = 1.0
    LoRa = 0.2  ← LoRa wins on power; WiFi wins on latency
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import time

from database import get_recent_packets, get_latest_routes, get_all_node_metrics

# ─── Constants ────────────────────────────────────────────────────────────────
PROTOCOL_POWER = {1: 0.5, 2: 1.0, 3: 0.2}   # BLE, WiFi, LoRa
GATEWAY_ID     = "GATEWAY"
STALE_ROUTE_SEC = 120   # routes older than this are flagged as stale


@dataclass
class RouteOption:
    path:          List[str]
    total_cost:    float
    avg_latency_ms: float
    hop_count:     int
    protocol_mix:  Dict[str, int]   # e.g. {"LoRa": 2, "WiFi": 1}
    freshness_sec: float            # age of the most recent packet on this path
    is_stale:      bool


@dataclass
class BestRouteReport:
    source:        str
    recommended:   Optional[RouteOption]
    alternatives:  List[RouteOption]
    flap_detected: bool
    generated_at:  str   # ISO timestamp


def _protocol_name(code: int) -> str:
    return {1: "BLE", 2: "WiFi", 3: "LoRa"}.get(code, "Unknown")


def _path_cost(path: List[str], avg_latency: float, protocol: int) -> float:
    """Cost = latency + power_cost * 10  (same formula as routing_table.py)."""
    power = PROTOCOL_POWER.get(protocol, 1.0)
    return avg_latency + (power * 10)


# ─── Core analysis ────────────────────────────────────────────────────────────

def analyse_routes() -> Dict[str, BestRouteReport]:
    """
    Returns a dict keyed by source node_id.
    Each value is a BestRouteReport with recommended + alternative routes.
    """
    packets = get_recent_packets(limit=500)
    routes  = get_latest_routes()
    metrics = {m["node_id"]: m for m in get_all_node_metrics()}

    # Group packets by src_id
    by_src: Dict[str, list] = {}
    for pkt in packets:
        by_src.setdefault(pkt["src_id"], []).append(pkt)

    reports: Dict[str, BestRouteReport] = {}
    now_ms = time.time() * 1000

    for src_id, pkts in by_src.items():

        # ── Build RouteOptions from distinct observed paths ──────────────────
        path_map: Dict[str, list] = {}
        for pkt in pkts:
            path_key = pkt.get("path", "[]")
            path_map.setdefault(path_key, []).append(pkt)

        options: List[RouteOption] = []
        for path_key, group in path_map.items():
            try:
                import json
                path = json.loads(path_key) if isinstance(path_key, str) else path_key
            except Exception:
                path = []

            latencies  = [p["latency_ms"] for p in group if p.get("latency_ms")]
            avg_lat    = sum(latencies) / len(latencies) if latencies else 0.0
            protocol   = group[0].get("protocol", 2)
            freshness  = (now_ms - max(p["received_at"] for p in group)) / 1000.0

            proto_counts: Dict[str, int] = {}
            for p in group:
                pname = _protocol_name(p.get("protocol", 0))
                proto_counts[pname] = proto_counts.get(pname, 0) + 1

            options.append(RouteOption(
                path           = path,
                total_cost     = round(_path_cost(path, avg_lat, protocol), 2),
                avg_latency_ms = round(avg_lat, 2),
                hop_count      = len(path),
                protocol_mix   = proto_counts,
                freshness_sec  = round(freshness, 1),
                is_stale       = freshness > STALE_ROUTE_SEC,
            ))

        options.sort(key=lambda o: o.total_cost)
        recommended  = options[0] if options else None
        alternatives = options[1:4]          # up to 3 alternatives

        # ── Detect flapping: top-2 routes cost within 5% of each other ───────
        flap = False
        if len(options) >= 2:
            c0, c1 = options[0].total_cost, options[1].total_cost
            if c0 > 0 and abs(c0 - c1) / c0 < 0.05:
                flap = True

        reports[src_id] = BestRouteReport(
            source        = src_id,
            recommended   = recommended,
            alternatives  = alternatives,
            flap_detected = flap,
            generated_at  = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

    return reports


def best_routes_to_dict(reports: Dict[str, BestRouteReport]) -> List[dict]:
    """Serialise to plain dicts for JSON responses."""
    def opt(o: Optional[RouteOption]):
        if o is None:
            return None
        return {
            "path":           o.path,
            "total_cost":     o.total_cost,
            "avg_latency_ms": o.avg_latency_ms,
            "hop_count":      o.hop_count,
            "protocol_mix":   o.protocol_mix,
            "freshness_sec":  o.freshness_sec,
            "is_stale":       o.is_stale,
        }

    return [
        {
            "source":       r.source,
            "recommended":  opt(r.recommended),
            "alternatives": [opt(a) for a in r.alternatives],
            "flap_detected": r.flap_detected,
            "generated_at": r.generated_at,
        }
        for r in reports.values()
    ]

# ─── Node health ──────────────────────────────────────────────────────────────

@dataclass
class NodeHealth:
    node_id:        str
    status:         str    # "online" | "degraded" | "offline"
    last_seen_sec:  float
    avg_latency_ms: float
    avg_rssi:       float
    packet_loss_pct: float
    protocol:       int


def compute_node_health(node_metrics: list) -> list[NodeHealth]:
    """
    Takes the raw rows from get_all_node_metrics() and returns
    a NodeHealth object for each node.

    Status thresholds:
        online   — last seen < 30s ago,  loss < 10%
        degraded — last seen < 120s ago, loss < 40%
        offline  — anything worse
    """
    now_ms = time.time() * 1000
    nodes  = []

    for m in node_metrics:
        age_sec = (now_ms - (m.get("last_seen") or 0)) / 1000.0
        loss    = m.get("packet_loss_pct", 0.0)

        if age_sec < 30 and loss < 10:
            status = "online"
        elif age_sec < 120 and loss < 40:
            status = "degraded"
        else:
            status = "offline"

        nodes.append(NodeHealth(
            node_id         = m["node_id"],
            status          = status,
            last_seen_sec   = round(age_sec, 1),
            avg_latency_ms  = round(m.get("avg_latency_ms", 0.0), 2),
            avg_rssi        = round(m.get("avg_rssi", 0.0), 1),
            packet_loss_pct = round(loss, 2),
            protocol        = m.get("protocol", 0),
        ))

    return nodes


def health_matrix_to_dict(nodes: list[NodeHealth]) -> list[dict]:
    """Serialise NodeHealth list to plain dicts for JSON responses."""
    return [
        {
            "node_id":         n.node_id,
            "status":          n.status,
            "last_seen_sec":   n.last_seen_sec,
            "avg_latency_ms":  n.avg_latency_ms,
            "avg_rssi":        n.avg_rssi,
            "packet_loss_pct": n.packet_loss_pct,
            "protocol":        n.protocol,
        }
        for n in nodes
    ]