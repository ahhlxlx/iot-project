"""
gateway/protocol_bridge.py
Translates raw on-wire messages from each protocol into the
canonical packet dict that gateway_receiver.forward_to_backend() expects.

This keeps all protocol-specific parsing in one place so
gateway_receiver.py stays protocol-agnostic.

Supported protocols
-------------------
  BLE  (protocol = 1) — JSON over serial / UART characteristic
  WiFi (protocol = 2) — JSON over UDP (already normalised by nodes)
  LoRa (protocol = 3) — JSON over serial prefixed with "RECV:"
"""

from __future__ import annotations
import json
import time
import logging
from typing import Optional

log = logging.getLogger(__name__)

# Protocol code constants (must match packet_format.py)
PROTO_BLE  = 1
PROTO_WIFI = 2
PROTO_LORA = 3

GATEWAY_DEST_IDS = {"GATEWAY", 0xFF}   # accepted dest_id values


class BridgeError(Exception):
    """Raised when a raw message cannot be translated."""


# ─── Generic helpers ──────────────────────────────────────────────────────────

def _safe_json(raw: str | bytes) -> dict:
    """Decode bytes and parse JSON, raising BridgeError on failure."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="ignore")
    raw = raw.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise BridgeError(f"JSON parse error: {e}  raw={raw[:80]!r}")


def _assert_data_packet(msg: dict):
    """Raise BridgeError if this is not a DATA packet destined for the gateway."""
    if msg.get("type") != "DATA":
        raise BridgeError(f"Not a DATA packet (type={msg.get('type')!r})")
    if msg.get("dest_id") not in GATEWAY_DEST_IDS:
        raise BridgeError(f"Packet not addressed to gateway (dest={msg.get('dest_id')!r})")


def _build_canonical(msg: dict, protocol: int, received_at_ms: float) -> dict:
    """Merge raw message fields into the canonical backend schema."""
    return {
        "src_id":       str(msg.get("src_id",      "UNKNOWN")),
        "dest_id":      str(msg.get("dest_id",      "GATEWAY")),
        "seq_num":      int(msg.get("seq_num",       0)),
        "protocol":     protocol,
        "hop_count":    int(msg.get("hop_count",     0)),
        "path":         msg.get("path",              []),
        "send_time_ms": int(msg.get("send_time_ms",  int(received_at_ms))),
        "rssi":         int(msg.get("rssi",           0)),
        "received_at":  received_at_ms,
    }


# ─── Per-protocol translators ─────────────────────────────────────────────────

def translate_wifi(raw: str | bytes,
                   received_at_ms: Optional[float] = None) -> dict:
    """
    WiFi nodes already send a well-formed JSON DATA packet over UDP.
    This function just validates and canonicalises it.

    Parameters
    ----------
    raw            : JSON bytes/string from the UDP socket
    received_at_ms : epoch timestamp in ms (defaults to now)
    """
    if received_at_ms is None:
        received_at_ms = time.time() * 1000

    msg = _safe_json(raw)
    _assert_data_packet(msg)
    return _build_canonical(msg, PROTO_WIFI, received_at_ms)


def translate_lora(serial_line: str,
                   received_at_ms: Optional[float] = None) -> dict:
    """
    LoRa messages arrive from the Arduino over serial as:
        RECV:<json_payload>

    The serial_line passed in may already have "RECV:" stripped by
    gateway_receiver.serial_listener, or may still have it — both are handled.

    Parameters
    ----------
    serial_line    : raw line from serial port
    received_at_ms : epoch timestamp in ms (defaults to now)
    """
    if received_at_ms is None:
        received_at_ms = time.time() * 1000

    line = serial_line.strip()
    if line.startswith("RECV:"):
        line = line[5:]

    msg = _safe_json(line)
    _assert_data_packet(msg)

    canonical = _build_canonical(msg, PROTO_LORA, received_at_ms)
    # LoRa RSSI is often embedded in the raw serial output as "rssi" by the
    # Arduino sketch — honour it if present, otherwise leave as 0
    canonical["rssi"] = int(msg.get("rssi", 0))
    return canonical


def translate_ble(raw: str | bytes,
                  rssi: int = 0,
                  received_at_ms: Optional[float] = None) -> dict:
    """
    BLE packets are delivered as JSON over a UART/serial characteristic.
    The RSSI is typically measured separately by the BLE central and passed in.

    Parameters
    ----------
    raw            : JSON bytes/string from the BLE characteristic
    rssi           : RSSI measured by the BLE central (dBm, negative int)
    received_at_ms : epoch timestamp in ms (defaults to now)
    """
    if received_at_ms is None:
        received_at_ms = time.time() * 1000

    msg = _safe_json(raw)
    _assert_data_packet(msg)

    canonical = _build_canonical(msg, PROTO_BLE, received_at_ms)
    # BLE RSSI measured at central overrides any node-reported value
    if rssi != 0:
        canonical["rssi"] = rssi
    return canonical


# ─── Unified entry point ──────────────────────────────────────────────────────

TRANSLATORS = {
    PROTO_WIFI: translate_wifi,
    PROTO_LORA: translate_lora,
    PROTO_BLE:  translate_ble,
}


def translate(raw: str | bytes,
              protocol: int,
              **kwargs) -> Optional[dict]:
    """
    Route raw message to the correct protocol translator.

    Parameters
    ----------
    raw      : raw message from the network interface
    protocol : 1 = BLE, 2 = WiFi, 3 = LoRa
    **kwargs : extra args forwarded to the translator
               (e.g. rssi=<int> for BLE, received_at_ms=<float> for all)

    Returns
    -------
    dict  — canonical packet ready for forward_to_backend(), or
    None  — if the message should be silently dropped (e.g. HELLO)
    """
    translator = TRANSLATORS.get(protocol)
    if translator is None:
        log.warning("Unknown protocol %d — dropping", protocol)
        return None

    try:
        return translator(raw, **kwargs)
    except BridgeError as e:
        log.debug("Bridge drop [proto=%d]: %s", protocol, e)
        return None
    except Exception as e:
        log.error("Unexpected bridge error [proto=%d]: %s", protocol, e)
        return None