"""Strict classic-PCAP parser (Ethernet/IPv4/TCP + HTTP/1.x).

Deliberately minimal and auditable: no pcapng, no retransmission-aware
reassembly. Frames that cannot be parsed are counted in the summary.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, Optional

MAX_PACKET = 65535
MAX_STREAM_BYTES = 2 * 1024 * 1024
MAX_STREAMS = 20000

# magic as read via little-endian uint32
_MAGIC_US_LE = 0xA1B2C3D4
_MAGIC_US_BE = 0xD4C3B2A1
_MAGIC_NS_LE = 0xA1B23C4D
_MAGIC_NS_BE = 0x4D3CB2A1


@dataclass
class HTTPMessage:
    is_request: bool
    method: str = ""
    path: str = ""
    version: str = ""
    status: int = 0
    headers: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class ParsedHTTP:
    stream_key: str
    request: Optional[HTTPMessage]
    response: Optional[HTTPMessage]


@dataclass
class PcapSummary:
    packets: int = 0
    skipped_frames: int = 0
    tcp_streams: int = 0
    http_transactions: int = 0
    notes: list[str] = field(default_factory=list)


def _global_header(data: bytes) -> str:
    if len(data) < 24:
        raise ValueError("pcap too short")
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic == _MAGIC_US_LE:
        return "<"
    if magic == _MAGIC_US_BE:
        return ">"
    if magic == _MAGIC_NS_LE:
        return "<"
    if magic == _MAGIC_NS_BE:
        return ">"
    raise ValueError("not a classic pcap (pcapng unsupported; convert first)")


def _packets(data: bytes, endian: str) -> Iterator[bytes]:
    off = 24
    n = len(data)
    while off + 16 <= n:
        _ts, _tf, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        if incl > MAX_PACKET or off + incl > n:
            return
        yield data[off:off + incl]
        off += incl


def _eth(frame: bytes) -> Optional[bytes]:
    if len(frame) < 14:
        return None
    et = struct.unpack_from("!H", frame, 12)[0]
    payload = frame[14:]
    while et == 0x8100 and len(payload) >= 4:
        et = struct.unpack_from("!H", payload, 2)[0]
        payload = payload[4:]
    return payload if et == 0x0800 else None


def _ipv4(pkt: bytes) -> Optional[tuple[str, str, int, bytes]]:
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if ihl < 20 or len(pkt) < ihl:
        return None
    src = ".".join(str(b) for b in pkt[12:16])
    dst = ".".join(str(b) for b in pkt[16:20])
    return src, dst, pkt[9], pkt[ihl:]


def _tcp(seg: bytes) -> Optional[tuple[int, int, bytes]]:
    if len(seg) < 20:
        return None
    sport, dport = struct.unpack_from("!HH", seg, 0)
    off = (seg[12] >> 4) * 4
    if off < 20 or len(seg) < off:
        return None
    return sport, dport, seg[off:]


@dataclass
class _Stream:
    client: bytearray = field(default_factory=bytearray)
    server: bytearray = field(default_factory=bytearray)


def extract_http(data: bytes) -> tuple[list[ParsedHTTP], PcapSummary]:
    summary = PcapSummary()
    endian = _global_header(data)
    streams: dict[tuple, _Stream] = {}
    for frame in _packets(data, endian):
        summary.packets += 1
        ip = _eth(frame)
        if ip is None:
            summary.skipped_frames += 1
            continue
        parsed = _ipv4(ip)
        if parsed is None or parsed[2] != 6:
            summary.skipped_frames += 1
            continue
        src, dst, _proto, l4 = parsed
        tcp = _tcp(l4)
        if tcp is None or not tcp[2]:
            continue
        sport, dport, payload = tcp
        if dport < sport:
            st = streams.setdefault((src, sport, dst, dport), _Stream())
            st.client += payload
        else:
            st = streams.setdefault((dst, dport, src, sport), _Stream())
            st.server += payload
        if len(streams) > MAX_STREAMS:
            summary.notes.append("stream cap reached; truncated")
            break
    out: list[ParsedHTTP] = []
    for key, st in streams.items():
        summary.tcp_streams += 1
        req = parse_http(bytes(st.client[:MAX_STREAM_BYTES]), True)
        resp = parse_http(bytes(st.server[:MAX_STREAM_BYTES]), False)
        if req or resp:
            if req and resp:
                summary.http_transactions += 1
            out.append(ParsedHTTP(
                f"{key[0]}:{key[1]}->{key[2]}:{key[3]}", req, resp))
    return out, summary


def parse_http(buf: bytes, is_request: bool) -> Optional[HTTPMessage]:
    if not buf:
        return None
    head_end = buf.find(b"\r\n\r\n")
    if head_end == -1 or head_end > 65536:
        return None
    head = buf[:head_end].decode("latin-1", errors="replace")
    lines = [ln for ln in head.split("\r\n") if ln.strip()]
    if not lines:
        return None
    msg = HTTPMessage(is_request=is_request)
    parts = lines[0].split()
    if is_request:
        if len(parts) < 2 or not parts[0].isupper():
            return None
        msg.method, msg.path = parts[0], parts[1]
        msg.version = parts[2] if len(parts) > 2 else "HTTP/1.0"
        if not msg.version.startswith("HTTP/"):
            return None
    else:
        if len(parts) < 2 or not parts[0].startswith("HTTP/"):
            return None
        try:
            msg.status = int(parts[1])
        except ValueError:
            return None
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            msg.headers.append((k.strip().lower(), v.strip()))
    return msg
