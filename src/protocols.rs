use crate::types::Protocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// Try to identify protocol and obtain a banner by passively reading first,
/// then sending light probes (HTTP HEAD, Telnet CRLF, TLS ClientHello) when appropriate.
pub async fn identify_and_banner(
    stream: &mut TcpStream,
    port: u16,
    max_bytes: usize,
    op_timeout: Duration,
) -> (Option<Protocol>, Option<String>) {
    // First, try to read any immediate banner without sending data (e.g., SSH, SMTP, Telnet IAC)
    match read_some(stream, max_bytes, op_timeout).await {
        Ok(buf) if !buf.is_empty() => {
            let (proto, banner) = detect_from_bytes(&buf, port);
            let banner_s = to_safe_string(&buf);
            return (Some(proto), Some(banner.unwrap_or(banner_s)));
        }
        _ => {}
    }

    // If nothing came in, try protocol-specific probes
    // 0) DNS-over-TCP probe if port suggests DNS
    if port == 53 {
        if let Ok((proto, banner)) = dns_probe(stream, max_bytes, op_timeout).await {
            return (Some(proto), banner);
        }
    }

    // 1) HTTP probe
    if let Ok((proto, banner)) = http_probe(stream, max_bytes, op_timeout).await {
        return (Some(proto), banner);
    }

    // 2) Telnet probe (send CRLF to coax a login/banner)
    if let Ok((proto, banner)) = telnet_probe(stream, max_bytes, op_timeout).await {
        return (Some(proto), banner);
    }

    // 3) TLS probe (may succeed on TLS services like HTTPS, SMTPS, etc.)
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
    // Telnet often emits IAC (0xFF) negotiations or login prompts
    if buf.first() == Some(&0xff)
        || tw_contains_ci(buf, b"login:")
        || tw_contains_ci(buf, b"username:")
        || tw_contains_ci(buf, b"password:")
    {
        return (Protocol::Telnet, Some(to_safe_string(buf)));
    }
    // TLS servers typically wait for ClientHello; but if we received TLS alert or handshake, detect
    if buf.get(0) == Some(&0x16) && matches!(buf.get(1), Some(0x03)) {
        return (Protocol::Tls, Some(hex_preview(buf)));
    }
    // DNS over TCP likely starts with 2-byte length prefix, then 12-byte header where QR bit may be 1 in responses.
    if buf.len() >= 14 {
        let header_start = 2; // after TCP length prefix
        let flags_hi = buf.get(header_start + 2).copied().unwrap_or(0);
        let is_response = (flags_hi & 0x80) != 0; // QR bit
        if is_response && port_hint == 53 {
            return (Protocol::Dns, Some(hex_preview(buf)));
        }
    }
    // Heuristics by port
    match port_hint {
        80 | 8080 | 8000 | 8888 => (Protocol::Http, None),
        443 | 8443 => (Protocol::Https, None),
        22 => (Protocol::Ssh, None),
        23 => (Protocol::Telnet, None),
        25 | 587 | 465 => (Protocol::Smtp, None),
        53 => (Protocol::Dns, None),
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
    let probe = b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: ospine\r\nConnection: close\r\n\r\n";
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

// Case-insensitive ASCII search for needle in buf
fn tw_contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    let n = needle.iter().map(|b| b.to_ascii_lowercase()).collect::<Vec<u8>>();
    haystack
        .windows(n.len())
        .any(|w| w.iter().map(|b| b.to_ascii_lowercase()).eq(n.iter().cloned()))
}

async fn telnet_probe(
    stream: &mut TcpStream,
    max_bytes: usize,
    op_timeout: Duration,
) -> Result<(Protocol, Option<String>), ()> {
    // Send CRLF to prompt a banner/login from many Telnet daemons
    let probe = b"\r\n";
    if timeout(op_timeout, stream.write_all(probe)).await.is_err() {
        return Err(());
    }
    let _ = timeout(op_timeout, stream.flush()).await;

    match read_some(stream, max_bytes, op_timeout).await {
        Ok(buf) if !buf.is_empty() => {
            let is_telnet = buf.first() == Some(&0xff) // IAC
                || tw_contains_ci(&buf, b"login:")
                || tw_contains_ci(&buf, b"username:")
                || tw_contains_ci(&buf, b"password:");
            if is_telnet {
                return Ok((Protocol::Telnet, Some(to_safe_string(&buf))));
            }
            Err(())
        }
        _ => Err(()),
    }
}

async fn dns_probe(
    stream: &mut TcpStream,
    max_bytes: usize,
    op_timeout: Duration,
) -> Result<(Protocol, Option<String>), ()> {
    // Build a minimal DNS query over TCP for A record of example.com
    // DNS header: ID(2) | Flags(2: RD=1) | QDCOUNT=1 | ANCOUNT=0 | NSCOUNT=0 | ARCOUNT=0
    let mut msg: Vec<u8> = Vec::with_capacity(2 + 12 + 17);
    let id: u16 = 0x4f53; // 'OS'
    // Two-byte length prefix placeholder (we'll insert after building message)
    // Header
    let mut dns: Vec<u8> = Vec::with_capacity(12 + 17);
    dns.extend_from_slice(&id.to_be_bytes());
    dns.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    dns.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    dns.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    dns.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    dns.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    // Question: example.com, type A, class IN
    for label in [&b"example"[..], &b"com"[..]] {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label);
    }
    dns.push(0); // root
    dns.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
    dns.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    let len = dns.len() as u16;
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(&dns);

    if timeout(op_timeout, stream.write_all(&msg)).await.is_err() {
        return Err(());
    }
    let _ = timeout(op_timeout, stream.flush()).await;

    // Read some response bytes
    let buf = match read_some(stream, max_bytes.saturating_add(2), op_timeout).await {
        Ok(b) if !b.is_empty() => b,
        _ => return Err(()),
    };

    // Try to parse DNS over TCP header
    let (header_start, total_len_ok) = if buf.len() >= 2 {
        let total = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if buf.len() >= 2 + 12 { (2usize, buf.len() >= 2 + total) } else { (2usize, false) }
    } else { (0usize, false) };

    if buf.len() < header_start + 12 { return Err(()); }
    let flags_hi = buf[header_start + 2];
    let flags_lo = buf[header_start + 3];
    let qr = (flags_hi & 0x80) != 0;
    let rcode = flags_lo & 0x0f;
    let qdcount = u16::from_be_bytes([buf[header_start + 4], buf[header_start + 5]]);
    let ancount = u16::from_be_bytes([buf[header_start + 6], buf[header_start + 7]]);
    let resp_id = u16::from_be_bytes([buf[header_start + 0], buf[header_start + 1]]);

    if !qr { return Err(()); }
    if resp_id != id { /* not fatal, some servers may rewrite ID behind proxies */ }

    let banner = Some(format!(
        "dns id=0x{resp_id:04x} qd={qd} an={an} rcode={rcode}{}",
        if total_len_ok { " complete" } else { "" },
        qd = qdcount,
        an = ancount
    ));

    Ok((Protocol::Dns, banner))
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
