# ospine
# Open Source Port Interrogation & Network Enumeration

A basic, fast, asynchronous port scanner with:
- Multi-threaded concurrency (Tokio multi-thread runtime)
- Protocol identification (HTTP, HTTPS/TLS, SSH, SMTP heuristics)
- Header/packet inspection via lightweight probes
- Banner grabbing (passive read first, then protocol-specific probes)

## Build

Requires Rust 1.74+ (edition 2021).

```
cargo build --release
```

## Usage

```
ospine <target> [OPTIONS]

Arguments:
  <target>  Target host (IP or hostname)

Options:
  -p, --ports <PORTS>        Ports to scan (e.g. 80,443,8000-8100) [default: 1-1024]
  -P, --popular              Scan only popular ports (overrides --ports when set)
  -c, --concurrency <N>      Max concurrent connections [default: 512]
  -t, --timeout-ms <MS>      Per-port timeout in milliseconds [default: 1200]
  -b, --banner-bytes <N>     Max bytes to read for banners [default: 512]
  -o, --open-only            Output only open ports (filters out closed/timeouts)
  -j, --json                 Output JSON instead of human-readable lines
  -h, --help                 Print help
  -V, --version              Print version
```

Examples:

```
# Scan the first 1024 ports on example.org
ospine example.org

# Scan common web ports with JSON output
ospine 93.184.216.34 -p 80,443,8080,8443 -j

# Scan a range with tighter timeout and higher concurrency
ospine localhost -p 1-65535 -t 500 -c 1024
```

## Output

Human-readable (default):
```
example.org:22 open [ssh] — SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n
example.org:80 open [http] — HTTP/1.1 301 Moved Permanently\r\n...
example.org:443 open [tls] — hex:160303...
example.org:25 closed
```

JSON (`-j`):
```
{
  "results": [
    {"target":"example.org","port":22,"open":true,"protocol":"ssh","banner":"SSH-2.0-...","error":null},
    {"target":"example.org","port":25,"open":false,"protocol":null,"banner":null,"error":"timeout"}
  ]
}
```

## Design

- Concurrency: semaphore-limited task fan-out using Tokio multi-thread runtime.
- Detection: passive banner read first; then probes: HTTP HEAD, minimal TLS ClientHello.
- Heuristics: basic port-to-protocol hints (22, 80, 443, 25, etc.).
- Extensible: add detectors in `src/protocols.rs` and wire into `identify_and_banner()`.

## Roadmap

- UDP scanning and protocol probes
- Service fingerprinting (more protocols: MySQL, PostgreSQL, Redis, RDP, SMB, MQTT, etc.)
- TLS SNI-based probing and certificate parsing
- Rate limiting per host/network, CIDR/host list inputs
- Output formats (NDJSON, CSV) and machine-readable error codes
- Tests and benchmarks

## Legal

Use responsibly. Only scan systems you own or are explicitly authorized to test. Unauthorized scanning may be illegal or violate terms of service.
