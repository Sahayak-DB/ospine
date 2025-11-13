use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::{Semaphore, Mutex};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PortSpec {
    List(Vec<u16>),
}

#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub target: String,
    pub port_spec: PortSpec,
    pub concurrency: usize,
    pub timeout: Duration,
    pub banner_read_len: usize,
    /// When true, perform only passive reads (no active protocol probes)
    pub passive: bool,
    // Global semaphore to enforce a process-wide connection cap
    pub global_limit: Arc<Semaphore>,
    // Global rate limiter to cap connection attempts per second
    pub rate_limiter: Arc<RateLimiter>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Protocol {
    Http,
    Https,
    Ssh,
    Smtp,
    Tls,
    Telnet,
    Dns,
    Mysql,
    Unknown,
}

impl Display for Protocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Ssh => "ssh",
            Protocol::Smtp => "smtp",
            Protocol::Tls => "tls",
            Protocol::Telnet => "telnet",
            Protocol::Dns => "dns",
            Protocol::Mysql => "mysql",
            Protocol::Unknown => "unknown",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub port: u16,
    pub open: bool,
    pub protocol: Option<Protocol>,
    pub banner: Option<String>,
    pub error: Option<String>,
}

// Simple global token bucket-like rate limiter (per-second window)
#[derive(Debug)]
pub struct RateLimiter {
    inner: Mutex<RateInner>,
}

#[derive(Debug)]
struct RateInner {
    rate_per_sec: u64,
    window_start: Instant,
    count_in_window: u64,
}

impl RateLimiter {
    pub fn new(rate_per_sec: u64) -> Self {
        Self {
            inner: Mutex::new(RateInner {
                rate_per_sec: rate_per_sec.max(1),
                window_start: Instant::now(),
                count_in_window: 0,
            }),
        }
    }

    /// Acquire one rate token. Waits until within the allowed rate.
    pub async fn acquire(&self) {
        loop {
            // Scope the lock to minimal section
            let mut guard = self.inner.lock().await;
            let now = Instant::now();
            let elapsed = now.duration_since(guard.window_start);
            if elapsed >= Duration::from_secs(1) {
                // Start a new window
                guard.window_start = now;
                guard.count_in_window = 0;
            }

            if guard.count_in_window < guard.rate_per_sec {
                guard.count_in_window += 1;
                // token acquired
                return;
            }

            // Need to wait until the window resets
            let sleep_dur = Duration::from_secs(1).saturating_sub(elapsed);
            drop(guard); // release the lock while sleeping
            tokio::time::sleep(sleep_dur).await;
            // and loop to try again
        }
    }
}
