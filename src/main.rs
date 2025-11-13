use anyhow::Result;
use clap::{ArgAction, Parser};
use std::str::FromStr;
use std::time::Duration;
use ipnet::IpNet;

mod scanner;
mod protocols;
mod types;

use scanner::scan_ports;
use types::{PortSpec, ScanConfig, ScanResult, ScanOutput};
use futures::stream::{self, StreamExt};
use std::io::{self, Write};
use std::fs::File;
use std::io::BufWriter;

// Build-time version: Major.Minor.Patch.Build
const APP_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), ".", env!("APP_BUILD"));

// Popular TCP ports list used by --popular flag
const POPULAR_PORTS: &[u16] = &[
    20,21,22,23,25,53,67,68,69,80,110,111,123,135,137,138,139,143,161,162,443,445,500,514,520,631,993,995,1434,1723,1900,3306,3389,4500,5900,8080,49152,
];

#[derive(Parser, Debug)]
#[command(name = "ospine", version = APP_VERSION, about = "Open Source Port Interrogation & Network Enumeration")] 
struct Cli {
    /// Target (IP, hostname, or CIDR range)
    target: String,

    /// Ports to scan (e.g. 80,443,8000-8100). Comma-separated list and/or ranges
    #[arg(short, long, default_value = "1-1024")]
    ports: String,

    /// Scan only popular ports (overrides --ports when set)
    #[arg(short = 'P', long = "popular", action = ArgAction::SetTrue)]
    popular: bool,

    /// Max concurrent connections
    #[arg(short = 'c', long, default_value_t = 512)]
    concurrency: usize,

    /// Per-port timeout milliseconds
    #[arg(short = 't', long, default_value_t = 1200)]
    timeout_ms: u64,

    /// Bytes to read for banner/probe
    #[arg(
        short = 'b',
        long,
        default_value_t = 512_u32,
        value_parser = clap::value_parser!(u32).range(1..=16384),
    )]
    banner_bytes: u32,

    /// JSON output
    #[arg(short = 'j', long, action = ArgAction::SetTrue)]
    json: bool,

    /// Output only open ports (filters out closed/timeouts)
    #[arg(short = 'o', long = "open-only", action = ArgAction::SetTrue)]
    open_only: bool,

    /// Show raw banner text without escaping newlines or carriage returns (human-readable mode only)
    #[arg(short = 'r', long = "raw-banner", action = ArgAction::SetTrue)]
    raw_banner: bool,

    /// Save completed ScanOutput JSON artifact to this file when the scan finishes
    #[arg(short = 's', long = "save-file", default_value = "last_scan.output")]
    save_file: String,
}

fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let p = part.trim();
        if p.is_empty() { continue; }
        if let Some((start, end)) = p.split_once('-') {
            let s: u16 = start.parse()?;
            let e: u16 = end.parse()?;
            for port in s.min(e)..=s.max(e) {
                ports.push(port);
            }
        } else {
            ports.push(p.parse()?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn parse_targets(input: &str) -> Result<Vec<String>> {
    // Try CIDR first
    if let Ok(net) = IpNet::from_str(input) {
        // Put a safety cap to avoid accidental huge scans
        const MAX_HOSTS: usize = 100_000;
        let hosts: Vec<String> = net.hosts().map(|ip| ip.to_string()).collect();
        if hosts.len() > MAX_HOSTS {
            anyhow::bail!("CIDR expands to {} hosts which exceeds the safety cap of {}", hosts.len(), MAX_HOSTS);
        }
        return Ok(hosts);
    }
    // Otherwise, treat as single IP or hostname string
    Ok(vec![input.to_string()])
}

// Escape control characters so untrusted banners can't manipulate the terminal.
// - Converts '\\n', '\\r', and '\\t' into visible sequences ("\\n", "\\r", "\\t").
// - Converts other control bytes (including ESC) to hex escapes like "\\x1b".
// - Leaves printable Unicode characters as-is.
fn escape_nonprintable(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\n' => { out.push('\\'); out.push('n'); }
            '\r' => { out.push('\\'); out.push('r'); }
            '\t' => { out.push('\\'); out.push('t'); }
            c if c.is_control() => {
                // Render as \xNN for BMP control chars
                let v = c as u32;
                if v <= 0xFF {
                    use std::fmt::Write as _;
                    out.push('\\'); out.push('x');
                    let _ = write!(&mut out, "{v:02x}");
                } else {
                    // Fallback for any odd control-like codepoints
                    use std::fmt::Write as _;
                    out.push('\\'); out.push('u'); out.push('{');
                    let _ = write!(&mut out, "{v:x}");
                    out.push('}');
                }
            }
            _ => out.push(ch),
        }
    }
    out
}

#[tokio::main(flavor = "multi_thread")] 
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let ports = if cli.popular {
        let mut v = POPULAR_PORTS.to_vec();
        v.sort_unstable();
        v.dedup();
        v
    } else {
        parse_ports(&cli.ports)?
    };

    let targets = parse_targets(&cli.target)?;

    // Global target concurrency limit to mitigate resource exhaustion
    const MAX_TARGET_CONCURRENCY: usize = 1_000;
    let target_concurrency = MAX_TARGET_CONCURRENCY.min(targets.len().max(1));

    // Prepare a stream of scan futures and buffer them with the global limit
    let ports_arc = ports.clone();
    let target_stream = stream::iter(targets.into_iter().map(move |t| {
        let cfg = ScanConfig {
            target: t,
            port_spec: PortSpec::List(ports_arc.clone()),
            concurrency: cli.concurrency,
            timeout: Duration::from_millis(cli.timeout_ms),
            banner_read_len: cli.banner_bytes as usize,
        };
        async move { scan_ports(cfg).await }
    }));

    let mut in_flight = target_stream.buffer_unordered(target_concurrency);

    // Prepare accumulation for final artifact and temp streaming persistence
    let mut all_results: Vec<ScanResult> = Vec::new();
    let tmp_file = File::create("output.tmp")?;
    let mut tmp_writer = BufWriter::new(tmp_file);

    // Streaming output: do not accumulate all results in memory
    let mut first_json_item = true;
    if cli.json {
        // Start streaming a JSON object with a results array
        print!("{{\"results\":[");
        io::stdout().flush().ok();
    }

    while let Some(res) = in_flight.next().await {
        match res {
            Ok(mut list) => {
                if cli.open_only {
                    list.retain(|r| r.open);
                }

                if cli.json {
                    for r in list {
                        // Persist to temp file as NDJSON (one ScanResult per line)
                        let line = serde_json::to_string(&r)?;
                        writeln!(tmp_writer, "{}", line)?;
                        all_results.push(r.clone());
                        let line = serde_json::to_string(&r)?;
                        if !first_json_item { print!(","); }
                        print!("{}", line);
                        first_json_item = false;
                    }
                    // Flush periodically for streaming behavior
                    io::stdout().flush().ok();
                } else {
                    // For human-readable output, sort per-target ports for stability
                    list.sort_by(|a, b| a.target.cmp(&b.target).then(a.port.cmp(&b.port)));
                    for r in list {
                        // Persist to temp and accumulation as well in human-readable mode
                        let json_line = serde_json::to_string(&r)?;
                        writeln!(tmp_writer, "{}", json_line)?;
                        all_results.push(r.clone());
                        let status = if r.open { "open" } else { "closed" };
                        let mut line = format!("{}:{} {}", r.target, r.port, status);
                        if let Some(proto) = r.protocol {
                            line.push_str(&format!(" [{}]", proto));
                        }
                        if let Some(banner) = r.banner {
                            if cli.raw_banner {
                                let safe = escape_nonprintable(&banner);
                                line.push_str(&format!(" — {}", safe));
                            }
                        }
                        println!("{}", line);
                    }
                }
            }
            Err(e) => eprintln!("scan task error: {}", e),
        }
    }

    if cli.json {
        println!("]}}");
    }

    // Ensure temp file is flushed
    tmp_writer.flush().ok();

    // Write the final consolidated ScanOutput artifact
    let artifact = ScanOutput { results: all_results };
    let mut out = BufWriter::new(File::create(&cli.save_file)?);
    serde_json::to_writer(&mut out, &artifact)?;
    out.flush().ok();

    // Close and remove the temporary file
    drop(tmp_writer); // Ensure the file handle is closed before attempting removal (important on Windows)
    if let Err(e) = std::fs::remove_file("output.tmp") {
        eprintln!("warning: failed to remove temp file output.tmp: {}", e);
    }

    Ok(())
}
