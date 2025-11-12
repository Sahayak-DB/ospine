use crate::types::Protocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// Try to identify protocol and obtain a banner by passively reading first,
/// then sending light probes (HTTP HEAD, TLS ClientHello) when appropriate.
pub async fn identify_and_banner(
    stream: &mut TcpStream,
    port: u16,
    max_bytes: usize,
    op_timeout: Duration,
) -> (Option<Protocol>, Option<String>) {
    // First, try to read any immediate banner without sending data (e.g., SSH, SMTP)
    match read_some(stream, max_bytes, op_timeout).await {
        Ok(buf) if !buf.is_empty() => {
            let (proto, banner) = detect_from_bytes(&buf, port);
            let banner_s = to_safe_string(&buf);
            return (Some(proto), Some(banner.unwrap_or(banner_s)));
        }
        _ => {}
    }

    // If nothing came in, try protocol-specific probes
    // 1) HTTP probe
    if let Ok((proto, banner)) = http_probe(stream, max_bytes, op_timeout).await {
        return (Some(proto), banner);
    }

    // 2) TLS probe (may succeed on TLS services like HTTPS, SMTPS, etc.)
    if let Ok((proto, banner)) = tls_probe(stream, max_bytes, op_timeout).await {
        return (Some(proto), banner);
    }

    // If still unknown, mark as open/unknown without banner
    (Some(Protocol::Unknown), None)
}

fn detect_from_bytes(buf: &[u8], port_hint: u16) -> (Protocol, Option<String>) {
    // SSH servers send something like: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n
    if buf.starts_with(b"SSH-") {
        return (Protocol::Ssh, Some(to_safe_string(buf)));
    }
    // SMTP often starts with "220 <banner>\r\n"
    if buf.starts_with(b"220 ") {
        return (Protocol::Smtp, Some(to_safe_string(buf)));
    }
    // HTTP responses start with HTTP/1.x or HTTP/2 preface (unlikely without client preface)
    if buf.starts_with(b"HTTP/") {
        return (Protocol::Http, Some(to_safe_string(buf)));
    }
    // TLS servers typically wait for ClientHello; but if we received TLS alert or handshake, detect
    if buf.get(0) == Some(&0x16) && matches!(buf.get(1), Some(0x03)) {
        return (Protocol::Tls, Some(hex_preview(buf)));
    }
    // Heuristics by port
    match port_hint {
        80 | 8080 | 8000 | 8888 => (Protocol::Http, None),
        443 | 8443 => (Protocol::Https, None),
        22 => (Protocol::Ssh, None),
        25 | 587 | 465 => (Protocol::Smtp, None),
        _ => (Protocol::Unknown, None),
    }
}

async fn read_some(stream: &mut TcpStream, max_bytes: usize, op_timeout: Duration) -> Result<Vec<u8>, ()> {
    let mut buf = vec![0u8; max_bytes];
    match timeout(op_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.truncate(n);
            Ok(buf)
        }
        _ => Err(()),
    }
}

async fn http_probe(
    stream: &mut TcpStream,
    max_bytes: usize,
    op_timeout: Duration,
) -> Result<(Protocol, Option<String>), ()> {
    let probe = b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: ospine/0.1\r\nConnection: close\r\n\r\n";
    if timeout(op_timeout, stream.write_all(probe)).await.is_err() {
        return Err(());
    }
    if timeout(op_timeout, stream.flush()).await.is_err() {
        return Err(());
    }
    match read_some(stream, max_bytes, op_timeout).await {
        Ok(buf) if !buf.is_empty() => {
            if buf.starts_with(b"HTTP/") {
                let banner = Some(to_safe_string(&buf));
                return Ok((Protocol::Http, banner));
            }
            Err(())
        }
        _ => Err(()),
    }
}

async fn tls_probe(
    stream: &mut TcpStream,
    max_bytes: usize,
    op_timeout: Duration,
) -> Result<(Protocol, Option<String>), ()> {
    // Minimal TLS ClientHello (no SNI), works for many servers. Not a full handshake implementation.
    // This is a commonly used small ClientHello payload.
    const CLIENT_HELLO: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x31, // Handshake record, TLS 1.0, length 0x0031
        0x01, 0x00, 0x00, 0x2d, // ClientHello, length 0x002d
        0x03, 0x03, // TLS 1.2
        // Random (32 bytes)
        0x53, 0x43, 0x4e, 0x52, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x00, // session id length
        0x00, 0x04, // cipher suites length (4 bytes)
        0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
        0x01, // compression methods length
        0x00, // null compression
        0x00, 0x00, // extensions length = 0
    ];

    if timeout(op_timeout, stream.write_all(CLIENT_HELLO)).await.is_err() {
        return Err(());
    }
    let _ = timeout(op_timeout, stream.flush()).await;

    match read_some(stream, max_bytes, op_timeout).await {
        Ok(buf) if !buf.is_empty() => {
            if buf.get(0) == Some(&0x16) && matches!(buf.get(1), Some(0x03)) {
                return Ok((Protocol::Tls, Some(hex_preview(&buf))));
            }
            Err(())
        }
        _ => Err(()),
    }
}

fn to_safe_string(buf: &[u8]) -> String {
    // Convert to UTF-8 lossily and trim NULs
    let mut s = String::from_utf8_lossy(buf).to_string();
    s.truncate(s.trim_end_matches('\0').len());
    s
}

fn hex_preview(buf: &[u8]) -> String {
    const MAX: usize = 64;
    let take = buf.len().min(MAX);
    let mut out = String::from("hex:");
    for b in &buf[..take] {
        out.push_str(&format!("{:02x}", b));
    }
    if buf.len() > MAX { out.push_str("…"); }
    out
}
