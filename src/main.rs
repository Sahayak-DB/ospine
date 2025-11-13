use anyhow::{anyhow, Result};
use clap::{ArgAction, Parser};
use std::str::FromStr;
use std::time::Duration;
use ipnet::IpNet;

mod scanner;
mod protocols;
mod types;
mod config;

use scanner::scan_ports;
use types::{PortSpec, ScanConfig, RateLimiter};
use futures::stream::{self, StreamExt};
use std::io::{self, Write, BufRead};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, BufReader, Seek, SeekFrom};
use std::path::{PathBuf, Path};
use std::env::temp_dir;
use std::sync::Arc;
use tokio::sync::Semaphore;

// Build-time version: Major.Minor.Patch.Build
const APP_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), ".", env!("APP_BUILD"));

// Popular TCP ports list used by --popular flag
const POPULAR_PORTS: &[u16] = &[
    20,21,22,23,25,53,67,68,69,80,110,111,123,135,137,138,139,143,161,162,443,445,500,514,520,631,993,995,1434,1723,1900,3306,3389,4500,5900,8080,49152,
];

#[derive(Parser, Debug)]
#[command(name = "ospine", version = APP_VERSION, about = "Open Source Port Interrogation & Network Enumeration")] 
struct Cli {
    /// Target (IP, hostname, or CIDR range). If omitted, must be provided by config file.
    target: Option<String>,

    /// Ports to scan (e.g. 80,443,8000-8100). Comma-separated list and/or ranges
    #[arg(short, long)]
    ports: Option<String>,

    /// Scan only popular ports (overrides --ports when set)
    #[arg(short = 'P', long = "popular", action = ArgAction::SetTrue)]
    popular: bool,

    /// Max concurrent connections
    #[arg(short = 'c', long)]
    concurrency: Option<usize>,

    /// Per-port timeout milliseconds
    #[arg(short = 't', long)]
    timeout_ms: Option<u64>,

    /// Bytes to read for banner/probe
    #[arg(
        short = 'b',
        long,
        value_parser = clap::value_parser!(u32).range(1..=16384),
    )]
    banner_bytes: Option<u32>,

    /// Passive mode: do not send any probe data; only perform passive banner reads
    #[arg(long = "passive", action = ArgAction::SetTrue)]
    passive: bool,

    /// JSON output
    #[arg(short = 'j', long, action = ArgAction::SetTrue)]
    json: bool,

    /// Output only open ports (filters out closed/timeouts)
    #[arg(short = 'o', long = "open-only", action = ArgAction::SetTrue)]
    open_only: bool,

    /// Show raw banner text (human-readable mode only)
    #[arg(short = 'r', long = "raw-banner", action = ArgAction::SetTrue)]
    raw_banner: bool,

    /// Save completed JSON artifact to this file when the scan finishes
    #[arg(short = 's', long = "save-file")]
    save_file: Option<String>,

    /// Global cap on in-flight TCP connections across all targets
    #[arg(long = "max-connections")]
    max_connections: Option<usize>,

    /// Global rate limit for connection attempts per second
    #[arg(long = "rate")]
    rate: Option<u64>,

    /// Path to a configuration file (TOML). If not set, defaults to $XDG_CONFIG_HOME/ospine/config.toml when present.
    #[arg(long = "config", value_name = "PATH")]
    config_path: Option<PathBuf>,

    /// Write current effective configuration to the config file and exit.
    #[arg(long = "write-config", action = ArgAction::SetTrue)]
    write_config: bool,
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

    // Load config file if present
    use crate::config::{FileConfig, load_config, save_config};
    let file_cfg = match load_config(cli.config_path.as_deref().map(Path::as_ref)) {
        Ok(opt) => opt.unwrap_or_default(),
        Err(e) => {
            eprintln!("warning: failed to load config file: {e}");
            FileConfig::default()
        }
    };

    // Merge precedence: CLI > file > built-in defaults
    let target = match (&cli.target, &file_cfg.target) {
        (Some(t), _) => t.clone(),
        (None, Some(t)) => t.clone(),
        (None, None) => return Err(anyhow!("target is required (via CLI or config file)")),
    };

    let ports_spec = if cli.popular || file_cfg.popular.unwrap_or(false) {
        None
    } else {
        cli.ports.clone().or(file_cfg.ports.clone()).or(Some("1-1024".to_string()))
    };

    let popular = if cli.popular { true } else { file_cfg.popular.unwrap_or(false) };
    let concurrency = cli.concurrency.or(file_cfg.concurrency).unwrap_or(100);
    let timeout_ms = cli.timeout_ms.or(file_cfg.timeout_ms).unwrap_or(1000);
    let banner_bytes = cli.banner_bytes.or(file_cfg.banner_bytes).unwrap_or(512);
    let passive = if cli.passive { true } else { file_cfg.passive.unwrap_or(false) };
    let json = if cli.json { true } else { file_cfg.json.unwrap_or(false) };
    let open_only = if cli.open_only { true } else { file_cfg.open_only.unwrap_or(false) };
    let raw_banner = if cli.raw_banner { true } else { file_cfg.raw_banner.unwrap_or(false) };
    let save_file = cli.save_file.clone().or(file_cfg.save_file.clone()).unwrap_or_else(|| "last_scan.output".to_string());
    let max_connections = cli.max_connections.or(file_cfg.max_connections).unwrap_or(10_000);
    let rate = cli.rate.or(file_cfg.rate).unwrap_or(5_000);

    if cli.write_config {
        // Write effective config and exit
        let eff = FileConfig {
            target: Some(target.clone()),
            ports: ports_spec.clone(),
            popular: Some(popular),
            concurrency: Some(concurrency),
            timeout_ms: Some(timeout_ms),
            banner_bytes: Some(banner_bytes),
            passive: Some(passive),
            json: Some(json),
            open_only: Some(open_only),
            raw_banner: Some(raw_banner),
            save_file: Some(save_file.clone()),
            max_connections: Some(max_connections),
            rate: Some(rate),
        };
        let path = match save_config(&eff, cli.config_path.as_deref().map(Path::as_ref)) {
            Ok(p) => p,
            Err(e) => return Err(anyhow!("failed to write config: {e}")),
        };
        println!("wrote configuration to {}", path.display());
        return Ok(());
    }

    let ports = if popular {
        let mut v = POPULAR_PORTS.to_vec();
        v.sort_unstable();
        v.dedup();
        v
    } else {
        let spec = ports_spec.unwrap_or_else(|| "1-1024".to_string());
        parse_ports(&spec)?
    };

    let targets = parse_targets(&target)?;

    // Global target concurrency limit to mitigate resource exhaustion
    const MAX_TARGET_CONCURRENCY: usize = 1_000;
    let target_concurrency = MAX_TARGET_CONCURRENCY.min(targets.len().max(1));

    // Prepare a stream of scan futures and buffer them with the global limit
    let ports_arc = ports.clone();
    // Create a global semaphore to enforce the connection cap
    let global_limit = Arc::new(Semaphore::new(max_connections));
    // Create a global rate limiter shared across all targets
    let rate_limiter = Arc::new(RateLimiter::new(rate));

    let target_stream = stream::iter(targets.into_iter().map(move |t| {
        let cfg = ScanConfig {
            target: t,
            port_spec: PortSpec::List(ports_arc.clone()),
            concurrency: concurrency,
            timeout: Duration::from_millis(timeout_ms),
            banner_read_len: banner_bytes as usize,
            passive: passive,
            global_limit: global_limit.clone(),
            rate_limiter: rate_limiter.clone(),
        };
        async move { scan_ports(cfg).await }
    }));

    let mut in_flight = target_stream.buffer_unordered(target_concurrency);

    // Prepare temp streaming persistence for final artifact construction without in-memory aggregation
    // Create a randomized temp file in the OS temp directory with O_EXCL semantics to avoid clobber/symlink issues.
    let mut tmp_path: Option<PathBuf> = None;
    let mut tmp_file: Option<File> = None;
    // Attempt a few times to avoid extremely unlikely name collisions
    for attempt in 0..3u8 {
        let mut path = temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let name = format!("ospine.{pid}.{nanos}.{attempt}.ndjson.tmp");
        path.push(name);
        match OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
            Ok(f) => {
                tmp_path = Some(path);
                tmp_file = Some(f);
                break;
            }
            Err(_) => continue,
        }
    }
    let tmp_path = tmp_path.ok_or_else(|| anyhow::anyhow!("failed to create secure temp file after several attempts"))?;
    let tmp_file = tmp_file.expect("temp file handle must exist if path is set");
    let mut tmp_writer = BufWriter::new(tmp_file);

    // Streaming output: do not accumulate all results in memory
    let mut first_json_item = true;
    if json {
        // Start streaming a JSON object with a results array
        print!("{{\"results\":[");
        io::stdout().flush().ok();
    }

    while let Some(res) = in_flight.next().await {
        match res {
            Ok(mut list) => {
                if open_only {
                    list.retain(|r| r.open);
                }

                if json {
                    for r in list {
                        // Persist to temp file as NDJSON (one ScanResult per line)
                        let line = serde_json::to_string(&r)?;
                        writeln!(tmp_writer, "{}", line)?;
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
                        let status = if r.open { "open" } else { "closed" };
                        let mut line = format!("{}:{} {}", r.target, r.port, status);
                        if let Some(proto) = r.protocol {
                            line.push_str(&format!(" [{}]", proto));
                        }
                        if let Some(banner) = r.banner {
                            if raw_banner {
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

    if json {
        println!("]}}");
    }

    // Ensure temp file is flushed before reading it back; keep the handle and seek instead of reopening by path
    tmp_writer.flush().ok();
    // Recover the underlying File handle from BufWriter
    let mut tmp_file = match tmp_writer.into_inner() {
        Ok(f) => f,
        Err(e) => {
            // If into_inner fails (e.g., due to prior write error), propagate the underlying error
            return Err(e.into_error().into());
        }
    };
    // Rewind to the beginning for reading
    tmp_file.seek(SeekFrom::Start(0))?;
    let reader = BufReader::new(tmp_file);
    let mut out = BufWriter::new(File::create(&save_file)?);
    write!(&mut out, "{{\"results\":[")?;
    let mut first = true;
    for line_res in reader.lines() {
        let line = line_res?;
        if line.is_empty() { continue; }
        if !first { write!(&mut out, ",")?; }
        first = false;
        // Each line is already a serialized ScanResult JSON object
        write!(&mut out, "{}", line)?;
    }
    write!(&mut out, "]}}")?;
    out.flush().ok();

    // Remove the temporary file
    if let Err(e) = std::fs::remove_file(&tmp_path) {
        eprintln!(
            "warning: failed to remove temp file {}: {}",
            tmp_path.display(),
            e
        );
    }

    Ok(())
}
