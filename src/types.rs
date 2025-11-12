use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::time::Duration;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanOutput {
    pub results: Vec<ScanResult>,
}
