use crate::protocols::identify_and_banner;
use crate::types::{PortSpec, Protocol, ScanConfig, ScanResult};
use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::ToSocketAddrs;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use std::sync::Arc;
use tokio::time;

pub async fn scan_ports(cfg: ScanConfig) -> Result<Vec<ScanResult>> {
    let ports: Vec<u16> = match &cfg.port_spec {
        PortSpec::List(v) => v.clone(),
    };

    let sem = Arc::new(Semaphore::new(cfg.concurrency));

    let mut tasks = FuturesUnordered::new();
    for port in ports {
        let permit = sem.clone().acquire_owned().await.expect("semaphore not closed");
        let cfg_clone = cfg.clone();
        tasks.push(tokio::spawn(async move {
            let _p = permit; // hold until task ends
            scan_one(&cfg_clone, port).await
        }));
    }

    let mut results = Vec::new();
    while let Some(res) = tasks.next().await {
        match res {
            Ok(Ok(item)) => results.push(item),
            Ok(Err(e)) => results.push(ScanResult {
                target: cfg.target.clone(),
                port: 0,
                open: false,
                protocol: None,
                banner: None,
                error: Some(format!("task error: {}", e)),
            }),
            Err(join_err) => results.push(ScanResult {
                target: cfg.target.clone(),
                port: 0,
                open: false,
                protocol: None,
                banner: None,
                error: Some(format!("join error: {}", join_err)),
            }),
        }
    }

    // sort by port for stable output
    results.sort_by_key(|r| r.port);
    Ok(results)
}

async fn scan_one(cfg: &ScanConfig, port: u16) -> Result<ScanResult> {
    let target = cfg.target.clone();
    let addr = format!("{}:{}", target, port);

    let connect_res = time::timeout(cfg.timeout, TcpStream::connect(&addr)).await;
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
            let (protocol, banner) = identify_and_banner(&mut stream, port, cfg.banner_read_len, cfg.timeout).await;
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
