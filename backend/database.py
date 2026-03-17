"""
backend/database.py
SQLite persistence layer for IoT mesh network data.
Stores packets, per-node metrics, and route snapshots.
"""

import sqlite3
import threading
import time
from contextlib import contextmanager

DB_PATH = "iot_network.db"
_local = threading.local()


def get_connection() -> sqlite3.Connection:
    """Return a thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")   # better concurrency
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


@contextmanager
def db():
    """Context manager — yields a cursor and auto-commits/rolls back."""
    conn = get_connection()
    cur  = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


# ─── Schema ──────────────────────────────────────────────────────────────────

def init_db():
    """Create all tables if they do not already exist."""
    with db() as cur:

        # Raw packet log (one row per packet received at the gateway)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at   REAL    NOT NULL,          -- unix epoch (ms)
                src_id        TEXT    NOT NULL,
                dest_id       TEXT    NOT NULL,
                seq_num       INTEGER NOT NULL,
                protocol      INTEGER NOT NULL,          -- 1=BLE 2=WiFi 3=LoRa
                hop_count     INTEGER NOT NULL DEFAULT 0,
                path          TEXT    NOT NULL DEFAULT '[]',   -- JSON array
                send_time_ms  INTEGER NOT NULL DEFAULT 0,
                rssi          INTEGER NOT NULL DEFAULT 0,
                latency_ms    REAL    GENERATED ALWAYS AS
                                  (received_at - send_time_ms) STORED
            )
        """)

        # Per-node rolling metrics snapshot
        cur.execute("""
            CREATE TABLE IF NOT EXISTS node_metrics (
                node_id         TEXT PRIMARY KEY,
                last_seen       REAL,
                total_sent      INTEGER DEFAULT 0,
                total_received  INTEGER DEFAULT 0,
                avg_latency_ms  REAL    DEFAULT 0.0,
                avg_rssi        REAL    DEFAULT 0.0,
                protocol        INTEGER DEFAULT 0
            )
        """)

        # Route snapshot (best hop at a point in time)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS route_snapshots (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at   REAL NOT NULL,
                src_id        TEXT NOT NULL,
                next_hop      TEXT NOT NULL,
                cost          REAL NOT NULL
            )
        """)

        # Packet-loss tracking per (node, window)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS loss_windows (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id     TEXT NOT NULL,
                window_end  REAL NOT NULL,
                sent        INTEGER NOT NULL,
                received    INTEGER NOT NULL,
                loss_pct    REAL GENERATED ALWAYS AS
                                (CASE WHEN sent = 0 THEN 0.0
                                      ELSE (1.0 - CAST(received AS REAL)/sent)*100
                                 END) STORED
            )
        """)


# ─── Packet writes ────────────────────────────────────────────────────────────

def insert_packet(src_id, dest_id, seq_num, protocol,
                  hop_count, path, send_time_ms, rssi,
                  received_at=None):
    """Persist one incoming packet and update the node_metrics row."""
    if received_at is None:
        received_at = time.time() * 1000

    with db() as cur:
        cur.execute("""
            INSERT INTO packets
                (received_at, src_id, dest_id, seq_num, protocol,
                 hop_count, path, send_time_ms, rssi)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (received_at, src_id, dest_id, seq_num, protocol,
              hop_count, str(path), send_time_ms, rssi))

        latency = received_at - send_time_ms

        # Upsert node_metrics
        cur.execute("""
            INSERT INTO node_metrics (node_id, last_seen, total_sent,
                total_received, avg_latency_ms, avg_rssi, protocol)
            VALUES (?, ?, 1, 1, ?, ?, ?)
            ON CONFLICT(node_id) DO UPDATE SET
                last_seen      = excluded.last_seen,
                total_received = total_received + 1,
                avg_latency_ms = (avg_latency_ms * total_received + excluded.avg_latency_ms)
                                  / (total_received + 1),
                avg_rssi       = (avg_rssi * total_received + excluded.avg_rssi)
                                  / (total_received + 1),
                protocol       = excluded.protocol
        """, (src_id, received_at, latency, rssi, protocol))


# ─── Query helpers ────────────────────────────────────────────────────────────

def get_recent_packets(limit=50):
    with db() as cur:
        cur.execute("""
            SELECT * FROM packets ORDER BY received_at DESC LIMIT ?
        """, (limit,))
        return [dict(r) for r in cur.fetchall()]


def get_all_node_metrics():
    with db() as cur:
        cur.execute("SELECT * FROM node_metrics ORDER BY last_seen DESC")
        rows = [dict(r) for r in cur.fetchall()]
        # Attach packet-loss for each node
        # REPLACE WITH
        for row in rows:
            # Detect loss via sequence number gaps instead of timestamp presence
            cur.execute("""
                SELECT seq_num
                FROM   packets
                WHERE  src_id = ?
                ORDER  BY seq_num ASC
            """, (row["node_id"],))
            seqs = [r["seq_num"] for r in cur.fetchall()]

            if len(seqs) < 2:
                row["packet_loss_pct"] = 0.0
            else:
                expected = seqs[-1] - seqs[0] + 1          # full range including gaps
                received = len(seqs)                        # packets actually in DB
                loss_pct = (1 - received / expected) * 100
                row["packet_loss_pct"] = round(max(loss_pct, 0.0), 2)
        return rows


def get_latency_series(node_id, limit=100):
    """Return (received_at, latency_ms) pairs for a node — newest first."""
    with db() as cur:
        cur.execute("""
            SELECT received_at, latency_ms
            FROM   packets
            WHERE  src_id = ?
            ORDER  BY received_at DESC
            LIMIT  ?
        """, (node_id, limit))
        return [dict(r) for r in cur.fetchall()]


def get_packet_loss_per_node():
    with db() as cur:
        cur.execute("""
            SELECT
                src_id,
                COUNT(*)  AS total,
                ROUND(AVG(rssi), 1) AS avg_rssi
            FROM packets
            GROUP BY src_id
        """)
        return [dict(r) for r in cur.fetchall()]


def insert_route_snapshot(src_id, next_hop, cost):
    with db() as cur:
        cur.execute("""
            INSERT INTO route_snapshots (recorded_at, src_id, next_hop, cost)
            VALUES (?, ?, ?, ?)
        """, (time.time() * 1000, src_id, next_hop, cost))


def get_latest_routes():
    """Return the most recent route snapshot per source node."""
    with db() as cur:
        cur.execute("""
            SELECT r.*
            FROM   route_snapshots r
            INNER JOIN (
                SELECT src_id, MAX(recorded_at) AS latest
                FROM   route_snapshots
                GROUP  BY src_id
            ) m ON r.src_id = m.src_id AND r.recorded_at = m.latest
        """)
        return [dict(r) for r in cur.fetchall()]