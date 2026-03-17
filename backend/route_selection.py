"""
backend/route_selection.py
Server-side route analysis.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Optional
import time
import json

from database import get_recent_packets, get_latest_routes, get_all_node_metrics

# ─── Constants ────────────────────────────────────────────────────────────────
PROTOCOL_POWER  = {1: 0.5, 2: 1.0, 3: 0.2}
GATEWAY_ID      = "GATEWAY"
STALE_ROUTE_SEC = 120


@dataclass
class RouteOption:
    path:           List[str]
    total_cost:     float
    avg_latency_ms: float
    hop_count:      int
    protocol_mix:   Dict[str, int]
    freshness_sec:  float
    is_stale:       bool


@dataclass
class BestRouteReport:
    source:        str
    recommended:   Optional[RouteOption]
    alternatives:  List[RouteOption]
    flap_detected: bool
    generated_at:  str


def _protocol_name(code: int) -> str:
    return {1: "BLE", 2: "WiFi", 3: "LoRa"}.get(code, "Unknown")


def _path_cost(path: List[str], avg_latency: float, protocol: int) -> float:
    power = PROTOCOL_POWER.get(protocol, 1.0)
    return avg_latency + (power * 10)


def analyse_routes() -> Dict[str, BestRouteReport]:
    packets = get_recent_packets(limit=500)
    routes  = get_latest_routes()
    metrics = {m["node_id"]: m for m in get_all_node_metrics()}

    by_src: Dict[str, list] = {}
    for pkt in packets:
        by_src.setdefault(pkt["src_id"], []).append(pkt)

    reports: Dict[str, BestRouteReport] = {}
    now_ms = time.time() * 1000

    for src_id, pkts in by_src.items():
        path_map: Dict[str, list] = {}
        for pkt in pkts:
            path_key = pkt.get("path", "[]")
            path_map.setdefault(path_key, []).append(pkt)

        options: List[RouteOption] = []
        for path_key, group in path_map.items():
            try:
                path = json.loads(path_key) if isinstance(path_key, str) else path_key
            except Exception:
                path = []

            latencies = [p["latency_ms"] for p in group if p.get("latency_ms")]
            avg_lat   = sum(latencies) / len(latencies) if latencies else 0.0
            protocol  = group[0].get("protocol", 2)
            freshness = (now_ms - max(p["received_at"] for p in group)) / 1000.0

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
        alternatives = options[1:4]

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
            "source":        r.source,
            "recommended":   opt(r.recommended),
            "alternatives":  [opt(a) for a in r.alternatives],
            "flap_detected": r.flap_detected,
            "generated_at":  r.generated_at,
        }
        for r in reports.values()
    ]