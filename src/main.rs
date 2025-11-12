use anyhow::Result;
use clap::{ArgAction, Parser};
use std::str::FromStr;
use std::time::Duration;
use ipnet::IpNet;

mod scanner;
mod protocols;
mod types;

use scanner::scan_ports;
use types::{PortSpec, ScanConfig, ScanOutput};
use futures::stream::{FuturesUnordered, StreamExt};

// Popular TCP ports list used by --popular flag
const POPULAR_PORTS: &[u16] = &[
    20,21,22,23,25,53,67,68,69,80,110,111,123,135,137,138,139,143,161,162,443,445,500,514,520,631,993,995,1434,1723,1900,3306,3389,4500,5900,8080,49152,
];

#[derive(Parser, Debug)]
#[command(name = "ospine", version, about = "Open Source Port Interrogation & Network Enumeration")] 
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
    #[arg(short = 'b', long, default_value_t = 512)]
    banner_bytes: usize,

    /// JSON output
    #[arg(short = 'j', long, action = ArgAction::SetTrue)]
    json: bool,

    /// Output only open ports (filters out closed/timeouts)
    #[arg(short = 'o', long = "open-only", action = ArgAction::SetTrue)]
    open_only: bool,

    /// Show raw banner text without escaping newlines or carriage returns (human-readable mode only)
    #[arg(short = 'r', long = "raw-banner", action = ArgAction::SetTrue)]
    raw_banner: bool,
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

    // Run scans per target concurrently and aggregate
    let mut tasks = FuturesUnordered::new();
    for t in targets {
        let cfg = ScanConfig {
            target: t,
            port_spec: PortSpec::List(ports.clone()),
            concurrency: cli.concurrency,
            timeout: Duration::from_millis(cli.timeout_ms),
            banner_read_len: cli.banner_bytes,
        };
        tasks.push(tokio::spawn(scan_ports(cfg)));
    }

    let mut all_results = Vec::new();
    while let Some(res) = tasks.next().await {
        match res {
            Ok(Ok(mut list)) => all_results.append(&mut list),
            Ok(Err(e)) => eprintln!("scan task error: {}", e),
            Err(join_err) => eprintln!("scan task join error: {}", join_err),
        }
    }

    if cli.open_only {
        all_results.retain(|r| r.open);
    }

    if cli.json {
        let out = ScanOutput { results: all_results };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        // Sort output by target then port for stability
        all_results.sort_by(|a, b| a.target.cmp(&b.target).then(a.port.cmp(&b.port)));
        for r in all_results {
            let status = if r.open { "open" } else { "closed" };
            let mut line = format!("{}:{} {}", r.target, r.port, status);
            if let Some(proto) = r.protocol {
                line.push_str(&format!(" [{}]", proto));
            }
            if let Some(banner) = r.banner {
                if cli.raw_banner {
                    line.push_str(&format!(" — {}", banner));
                }
            }
            println!("{}", line);
        }
    }

    Ok(())
}
