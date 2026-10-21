//! Tiny HTTP/1.1 GET client used for public-IP lookup and HTTP ping tasks.
//! Avoids pulling a full HTTP stack into the agent binary.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Family, connect, tls};

#[derive(Debug, Clone, PartialEq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_url(url: &str) -> Option<Url> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        (false, url)
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let authority = authority.rsplit_once('@').map(|(_, a)| a).unwrap_or(authority);
    let (host, port) = if let Some(end) = authority.strip_prefix('[').and_then(|a| a.find(']')) {
        let host = &authority[1..end + 1];
        let port = authority[end + 2..].strip_prefix(':').and_then(|p| p.parse().ok());
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p.parse().ok()?)),
            None => (authority.to_string(), None),
        }
    };
    if host.is_empty() {
        return None;
    }
    let port = port.unwrap_or(if https { 443 } else { 80 });
    Some(Url { https, host, port, path: path.to_string() })
}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// GET `url`. When `read_body` is false, returns as soon as the status line arrives.
pub async fn get(url: &Url, family: Option<Family>, timeout: Duration, read_body: bool) -> io::Result<Response> {
    let fut = async {
        let tcp = connect(&url.host, url.port, family, timeout).await?;
        if url.https {
            let name = tls::server_name(&url.host).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let stream = tls::connector(false).connect(name, tcp).await?;
            exchange(stream, url, read_body).await
        } else {
            exchange(tcp, url, read_body).await
        }
    };
    tokio::time::timeout(timeout, fut).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "http timeout"))?
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, url: &Url, read_body: bool) -> io::Result<Response> {
    let host = if url.host.contains(':') { format!("[{}]", url.host) } else { url.host.clone() };
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: vespera-agent/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        url.path,
        env!("VESPERA_AGENT_VERSION")
    );
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if !read_body && buf.windows(2).any(|w| w == b"\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }
    let line_end = buf.windows(2).position(|w| w == b"\r\n").unwrap_or(buf.len());
    let status_line = String::from_utf8_lossy(&buf[..line_end]);
    let status = status_line
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad status line"))?;
    let body = match buf.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => buf[i + 4..].to_vec(),
        None => Vec::new(),
    };
    Ok(Response { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("https://example.com/a?b").unwrap();
        assert_eq!((u.https, u.host.as_str(), u.port, u.path.as_str()), (true, "example.com", 443, "/a?b"));
        let u = parse_url("example.com:8080").unwrap();
        assert_eq!((u.https, u.port, u.path.as_str()), (false, 8080, "/"));
        let u = parse_url("https://[2606:4700:4700::1111]/cdn-cgi/trace").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("2606:4700:4700::1111", 443));
        let u = parse_url("http://[::1]:81").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 81));
        assert!(parse_url("http://").is_none());
    }
}
