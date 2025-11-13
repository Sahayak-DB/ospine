# ospine
# Open Source Port Interrogation & Network Enumeration

A fast, asynchronous port scanner with probe detection support:
- Multi-threaded concurrency (Tokio multi-thread runtime)
- Protocol identification (HTTP, HTTPS/TLS, SSH, SMTP, Telnet heuristics)
- Header/packet inspection via lightweight probes
- Banner grabbing (passive read first, then protocol-specific probes)
- Configuration options for concurrency, safety and speed of scanning

## Build

Requires Rust 1.74+ (edition 2021).

```
cargo build --release
```

## Usage

```
ospine [target] [OPTIONS]

Arguments:
  [target]  Target (IP, hostname, or CIDR range). If omitted, must be provided by a config file.

Options:
  -p, --ports <PORTS>            Ports to scan (e.g. 80,443,8000-8100)
  -P, --popular                  Scan only popular ports (overrides --ports when set)
  -c, --concurrency <N>          Max concurrent connections per target
  -t, --timeout-ms <MS>          Per-port timeout in milliseconds
  -b, --banner-bytes <N>         Max bytes to read for banners
      --passive                  Passive mode: do not send any probes, only read banners
      --max-connections <N>      Global cap on in-flight TCP connections
      --rate <N>                 Global rate limit for connection attempts per second
  -o, --open-only                Output only open ports (filters out closed/timeouts)
  -r, --raw-banner               Show banner text in human-readable output (escaped)
  -j, --json                     Output JSON instead of human-readable lines
  -s, --save-file <PATH>         Save final JSON artifact to this file
      --config <PATH>            Path to a TOML config file (default: $XDG_CONFIG_HOME/ospine/config.toml if present)
      --write-config             Write current effective configuration to the config file and exit
  -h, --help                     Print help
  -V, --version                  Print version
```

Examples:

```
# Scan the first 1024 ports on example.org
ospine example.org

# Scan common web ports with JSON output
ospine 93.184.216.34 -p 80,443,8080,8443 -j

# Scan a range with tighter timeout and higher concurrency
ospine localhost -p 1-65535 -t 500 -c 1024

# Scan an entire CIDR (expands to all host IPs; safety cap applies)
ospine 192.168.1.0/28 -p 22,80,443

# Passive scan (no probes sent) with global safety limits
ospine example.org -p 1-1024 --passive --max-connections 2000 --rate 1000
```

## Configuration file

You can persist your favorite settings in a TOML configuration file. The default location is:
- Linux/macOS: `$XDG_CONFIG_HOME/ospine/config.toml` (typically `~/.config/ospine/config.toml`)
- Windows: `%APPDATA%/ospine/config/config.toml`

Precedence: CLI flags override the config file, which in turn overrides built-in defaults. Boolean flags from CLI can only enable features (no `--no-...` toggles yet).

Generate a config from your current CLI choices:

```
ospine example.org -p 22,80,443 -c 512 -t 750 --rate 2000 --write-config
# writes to default config path unless --config PATH is provided
```

Minimal example `config.toml`:

```
target = "example.org"
ports = "22,80,443,8080"
concurrency = 512
timeout_ms = 750
banner_bytes = 1024
json = true
open_only = true
save_file = "last_scan.json"
max_connections = 2000
rate = 2000
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
- Service fingerprinting (more protocols: PostgreSQL, Redis, RDP, SMB, MQTT, etc.)
- Scripting support for advanced scanning activity

## Legal

Use responsibly. Only scan systems you own or have explicit authorization in writing to test. Unauthorized scanning may be illegal or violate terms of service. Maintainers present this code without any warranty or recourse for its usage.


## Versioning (Major.Minor.Patch.Build)

The binary embeds a build number as the 4th segment of the semantic version: `Major.Minor.Patch.Build`.

How `Build` is determined at compile time:
- If one of these environment variables is set, it is used (in order of precedence):
  - `APP_BUILD` (explicit override)
  - `GITHUB_RUN_NUMBER` (GitHub Actions)
  - `CI_PIPELINE_IID` or `CI_JOB_ID` (GitLab CI)
  - `CIRCLE_BUILD_NUM` (CircleCI)
  - `BITBUCKET_BUILD_NUMBER` (Bitbucket Pipelines)
  - `BUILD_BUILDID` (Azure Pipelines)
  - `TEAMCITY_BUILD_ID` (TeamCity)
  - `DRONE_BUILD_NUMBER` (Drone CI)
  - `JENKINS_BUILD_NUMBER` or generic `BUILD_NUMBER` (Jenkins/legacy)
- Otherwise, the build script falls back to the local Git commit count: `git rev-list --count HEAD`.
- If neither is available, it uses `0`.

This is implemented by `build.rs`, which exports `APP_BUILD` as a compile-time environment variable consumed by the CLI metadata. You can see the final version with:

```
./target/debug/ospine --version
```

Local development examples:
- Ensure Git is available so the commit count can be used, or set `APP_BUILD` manually:
  - `APP_BUILD=123 cargo build`

CI example (GitHub Actions):

```
- name: Build
  run: cargo build --release
  # The build number will automatically come from $GITHUB_RUN_NUMBER
```

Note: The build script instructs Cargo to rerun when relevant env vars change or when Git `HEAD` moves, keeping the embedded version up to date across builds.

Audit:
```
cargo install cargo-audit
cargo audit --deny warnings
```