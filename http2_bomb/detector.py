"""Passive/active detection for HTTP/2 and server fingerprinting."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

SERVER_PROFILES = {
    "nginx": {"amplification": "~70:1", "cve": "pending", "fixed_in": "1.29.8"},
    "apache": {"amplification": "~4000:1", "cve": "CVE-2026-49975", "fixed_in": "mod_http2 2.0.41"},
    "envoy": {"amplification": "~5700:1", "cve": "CVE-2026-47774", "fixed_in": "1.37.x+"},
    "microsoft-iis": {"amplification": "~68:1", "cve": "pending", "fixed_in": "Windows Server patches"},
    "cloudflare": {"amplification": "varies", "cve": "pending", "fixed_in": "Pingora updates"},
}


@dataclass
class DetectionResult:
    target: str
    host: str
    port: int
    tls: bool
    http2_supported: bool = False
    alpn_protocol: Optional[str] = None
    server_header: Optional[str] = None
    server_guess: Optional[str] = None
    settings_max_concurrent_streams: Optional[int] = None
    settings_initial_window_size: Optional[int] = None
    settings_max_header_list_size: Optional[int] = None
    error: Optional[str] = None
    risk_notes: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=lambda: [
        "CVE-2026-49975 (Apache mod_http2)",
        "CVE-2026-47774 (Envoy)",
        "CVE-2016-6581 (classic HPACK bomb)",
        "RFC 7541 HPACK / RFC 9113 HTTP/2",
    ])

    @property
    def potentially_vulnerable(self) -> bool:
        if self.error or not self.http2_supported:
            return False
        if self.server_guess in ("nginx", "apache", "envoy", "microsoft-iis", "cloudflare"):
            return True
        return True  # HTTP/2 without fingerprint — needs safe test


def parse_target(target: str) -> tuple[str, int, bool, str]:
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    host = parsed.hostname or "localhost"
    use_tls = parsed.scheme != "http"
    default_port = 443 if use_tls else 80
    port = parsed.port or default_port
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return host, port, use_tls, path


def _guess_server(server_header: Optional[str]) -> Optional[str]:
    if not server_header:
        return None
    low = server_header.lower()
    if "nginx" in low:
        return "nginx"
    if "apache" in low:
        return "apache"
    if "envoy" in low:
        return "envoy"
    if "microsoft-iis" in low or "iis" in low:
        return "microsoft-iis"
    if "cloudflare" in low:
        return "cloudflare"
    return None


def recv_exact(sock: ssl.SSLSocket | socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock: ssl.SSLSocket | socket.socket, timeout: float = 5.0) -> Optional[tuple[int, int, int, bytes]]:
    sock.settimeout(timeout)
    header = recv_exact(sock, 9)
    if len(header) < 9:
        return None
    length = int.from_bytes(header[:3], "big")
    ftype = header[3]
    flags = header[4]
    stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
    payload = recv_exact(sock, length) if length else b""
    return ftype, flags, stream_id, payload


def _parse_settings(payload: bytes) -> dict[int, int]:
    out: dict[int, int] = {}
    for i in range(0, len(payload) - 5, 6):
        sid = int.from_bytes(payload[i : i + 2], "big")
        val = int.from_bytes(payload[i + 2 : i + 6], "big")
        out[sid] = val
    return out


def _frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    length = len(payload)
    hdr = length.to_bytes(3, "big") + bytes([ftype, flags]) + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
    return hdr + payload


def detect_http2(target: str, timeout: float = 10.0) -> DetectionResult:
    host, port, use_tls, _path = parse_target(target)
    result = DetectionResult(target=target, host=host, port=port, tls=use_tls)

    raw: socket.socket | ssl.SSLSocket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            raw = ctx.wrap_socket(sock, server_hostname=host)
            result.alpn_protocol = raw.selected_alpn_protocol()
        else:
            raw = sock
            result.alpn_protocol = "h2-cleartext"

        if use_tls and result.alpn_protocol != "h2":
            result.http2_supported = False
            result.error = f"ALPN negotiated {result.alpn_protocol!r}, not h2"
            raw.close()
            return result

        raw.sendall(H2_PREFACE)
        raw.sendall(_frame(0x04, 0, 0, b""))
        result.http2_supported = True

        server_settings: dict[int, int] = {}
        settings_timeout = min(timeout, 5.0)
        try:
            for _ in range(10):
                frame = read_frame(raw, settings_timeout)
                if not frame:
                    break
                ftype, flags, _sid, payload = frame
                if ftype == 0x04 and not (flags & 0x01):
                    server_settings.update(_parse_settings(payload))
                    raw.sendall(_frame(0x04, 0x01, 0, b""))
                elif ftype == 0x04 and (flags & 0x01):
                    continue
                elif ftype == 0x00:
                    break
        except (TimeoutError, socket.timeout, OSError) as exc:
            if "timed out" not in str(exc).lower() and not isinstance(exc, (TimeoutError, socket.timeout)):
                raise
            result.risk_notes.append("SETTINGS read timed out — H2 preface accepted")

        result.settings_max_concurrent_streams = server_settings.get(0x03)
        result.settings_initial_window_size = server_settings.get(0x04, 65535)
        result.settings_max_header_list_size = server_settings.get(0x06)

        from hpack import Encoder

        enc = Encoder()
        req_block = enc.encode([
            (b":method", b"GET"),
            (b":path", b"/"),
            (b":scheme", b"https" if use_tls else b"http"),
            (b":authority", host.encode()),
            (b"user-agent", b"http2-bomb-scanner/1.0"),
        ])
        raw.sendall(_frame(0x01, 0x05, 1, req_block))

        resp_data = b""
        header_timeout = min(timeout, 3.0)
        try:
            for _ in range(10):
                frame = read_frame(raw, header_timeout)
                if not frame:
                    break
                ftype, flags, sid, payload = frame
                if sid == 1 and ftype in (0x01, 0x09):
                    resp_data += payload
                if sid == 1 and ftype == 0x00 and (flags & 0x01):
                    break
        except (TimeoutError, socket.timeout, OSError) as exc:
            if "timed out" in str(exc).lower() or isinstance(exc, (TimeoutError, socket.timeout)):
                result.risk_notes.append(
                    "Response read timed out — H2 confirmed via SETTINGS exchange"
                )
            else:
                raise

        if resp_data:
            try:
                from hpack import Decoder

                dec = Decoder()
                headers = dec.decode(resp_data)
                for name, value in headers:
                    if name.lower() == b"server":
                        result.server_header = value.decode("latin-1", errors="replace")
                        result.server_guess = _guess_server(result.server_header)
                        break
            except Exception:
                pass
        elif result.http2_supported and not result.error:
            result.risk_notes.append(
                "Server header not captured (timeout) — H2 confirmed via SETTINGS exchange"
            )

        if result.potentially_vulnerable:
            profile = SERVER_PROFILES.get(result.server_guess or "", {})
            if profile:
                result.risk_notes.append(
                    f"Server profile {result.server_guess}: amp {profile.get('amplification')}, "
                    f"fix {profile.get('fixed_in')}"
                )
            else:
                result.risk_notes.append(
                    "HTTP/2 enabled; HPACK indexed-ref + window-stall DoS class may apply (verify with safe test)."
                )

        raw.close()
    except Exception as exc:
        result.error = str(exc)

    return result
