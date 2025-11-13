use crate::protocols::identify_and_banner;
use crate::types::{PortSpec, ScanConfig, ScanResult};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time;

pub async fn scan_ports(cfg: ScanConfig) -> Result<Vec<ScanResult>> {
    let ports: Vec<u16> = match &cfg.port_spec {
        PortSpec::List(v) => v.clone(),
    };

    // Shared results vector guarded by a mutex; avoids spawning one task per port up-front
    let results: Arc<Mutex<Vec<ScanResult>>> = Arc::new(Mutex::new(Vec::new()));

    // Process ports with bounded concurrency, avoiding massive task fan-out
    let results_cloned = results.clone();
    stream::iter(ports.into_iter())
        .for_each_concurrent(cfg.concurrency, move |port| {
            let cfg_clone = cfg.clone();
            let results_inner = results_cloned.clone();
            async move {
                // Perform the scan for a single port, handling errors inline
                let item = match scan_one(&cfg_clone, port).await {
                    Ok(it) => it,
                    Err(e) => ScanResult {
                        target: cfg_clone.target.clone(),
                        port,
                        open: false,
                        protocol: None,
                        banner: None,
                        error: Some(format!("task error: {}", e)),
                    },
                };
                // Push into results
                results_inner.lock().await.push(item);
            }
        })
        .await;

    // sort by port for stable output
    let mut out = results.lock().await.clone();
    out.sort_by_key(|r| r.port);
    Ok(out)
}

async fn scan_one(cfg: &ScanConfig, port: u16) -> Result<ScanResult> {
    let target = cfg.target.clone();

    // Global rate limit: acquire a token before attempting a connection.
    // Do this before acquiring the global connection permit so we don't hold
    // scarce connection slots while waiting for the next rate window.
    cfg.rate_limiter.acquire().await;

    // Acquire a global permit to enforce process-wide connection cap.
    // Held for the duration of this scan operation.
    let _global_permit = cfg
        .global_limit
        .clone()
        .acquire_owned()
        .await
        .expect("global semaphore not closed");

    // Use (host, port) tuple to let ToSocketAddrs handle IPv6 brackets and DNS resolution
    let connect_res = time::timeout(cfg.timeout, TcpStream::connect((target.as_str(), port))).await;
    match connect_res {
        Err(_) => Ok(ScanResult {
            target,
            port,
            open: false,
            protocol: None,
            banner: None,
            error: Some("timeout".into()),
        }),
        Ok(Err(e)) => Ok(ScanResult {
            target,
            port,
            open: false,
            protocol: None,
            banner: None,
            error: Some(e.to_string()),
        }),
        Ok(Ok(mut stream)) => {
            let (protocol, banner) = identify_and_banner(
                &mut stream,
                port,
                cfg.banner_read_len,
                cfg.timeout,
                cfg.passive,
            )
            .await;
            Ok(ScanResult {
                target,
                port,
                open: true,
                protocol,
                banner,
                error: None,
            })
        }
    }
}
