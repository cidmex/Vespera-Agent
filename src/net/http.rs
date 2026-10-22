//! Tiny HTTP/1.1 GET client used for public-IP lookup, HTTP ping tasks and
//! self-update downloads. Avoids pulling a full HTTP stack into the agent binary.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

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

fn err(kind: io::ErrorKind, msg: impl Into<String>) -> io::Error {
    io::Error::new(kind, msg.into())
}

/// Download `url` completely, following up to 5 redirects. Supports
/// `Content-Length`, chunked transfer encoding and read-to-close bodies.
pub async fn download(url: &str, max_bytes: usize, timeout: Duration) -> io::Result<Vec<u8>> {
    let fut = async {
        let mut current = url.to_string();
        for _ in 0..=5 {
            let u =
                parse_url(&current).ok_or_else(|| err(io::ErrorKind::InvalidInput, format!("bad url {current}")))?;
            let tcp = connect(&u.host, u.port, None, Duration::from_secs(15)).await?;
            let (status, location, body) = if u.https {
                let name = tls::server_name(&u.host).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                let stream = tls::connector(false).connect(name, tcp).await?;
                fetch_full(stream, &u, max_bytes).await?
            } else {
                fetch_full(tcp, &u, max_bytes).await?
            };
            match status {
                200 => return Ok(body),
                301 | 302 | 303 | 307 | 308 => {
                    let loc = location.ok_or_else(|| err(io::ErrorKind::InvalidData, "redirect without Location"))?;
                    current = resolve_location(&u, &loc);
                }
                s => return Err(err(io::ErrorKind::Other, format!("HTTP {s} for {current}"))),
            }
        }
        Err(err(io::ErrorKind::Other, "too many redirects"))
    };
    tokio::time::timeout(timeout, fut).await.map_err(|_| err(io::ErrorKind::TimedOut, "download timeout"))?
}

fn resolve_location(base: &Url, loc: &str) -> String {
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return loc.to_string();
    }
    let scheme = if base.https { "https" } else { "http" };
    if let Some(rest) = loc.strip_prefix("//") {
        return format!("{scheme}://{rest}");
    }
    let host = if base.host.contains(':') { format!("[{}]", base.host) } else { base.host.clone() };
    let default_port = if base.https { 443 } else { 80 };
    let authority = if base.port == default_port { host } else { format!("{host}:{}", base.port) };
    if loc.starts_with('/') {
        return format!("{scheme}://{authority}{loc}");
    }
    let dir = base.path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    format!("{scheme}://{authority}{dir}/{loc}")
}

/// One request; returns (status, Location header, body). Redirect bodies are not read.
async fn fetch_full<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    url: &Url,
    max_bytes: usize,
) -> io::Result<(u16, Option<String>, Vec<u8>)> {
    let host = if url.host.contains(':') { format!("[{}]", url.host) } else { url.host.clone() };
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: vespera-agent/{}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        url.path,
        env!("VESPERA_AGENT_VERSION")
    );
    s.write_all(req.as_bytes()).await?;
    let mut r = BufReader::new(s);

    let mut line = String::new();
    r.read_line(&mut line).await?;
    let status: u16 = line
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| err(io::ErrorKind::InvalidData, "bad status line"))?;
    let (mut length, mut chunked, mut location) = (None::<usize>, false, None);
    let mut header_bytes = 0;
    loop {
        line.clear();
        let n = r.read_line(&mut line).await?;
        header_bytes += n;
        if n == 0 || header_bytes > 64 * 1024 {
            return Err(err(io::ErrorKind::InvalidData, "truncated headers"));
        }
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            match k.as_str() {
                "content-length" => length = v.parse().ok(),
                "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
                "location" => location = Some(v.to_string()),
                _ => {}
            }
        }
    }
    if status != 200 {
        return Ok((status, location, Vec::new()));
    }

    let too_big = || err(io::ErrorKind::InvalidData, format!("body larger than {max_bytes} bytes"));
    let mut body = Vec::new();
    if chunked {
        loop {
            line.clear();
            r.read_line(&mut line).await?;
            let size_hex = line.trim().split(';').next().unwrap_or("");
            let size =
                usize::from_str_radix(size_hex, 16).map_err(|_| err(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                // Skip optional trailers.
                loop {
                    line.clear();
                    if r.read_line(&mut line).await? == 0 || line.trim().is_empty() {
                        break;
                    }
                }
                break;
            }
            if body.len() + size > max_bytes {
                return Err(too_big());
            }
            let start = body.len();
            body.resize(start + size, 0);
            r.read_exact(&mut body[start..]).await?;
            let mut crlf = [0u8; 2];
            r.read_exact(&mut crlf).await?;
        }
    } else if let Some(len) = length {
        if len > max_bytes {
            return Err(too_big());
        }
        body.resize(len, 0);
        r.read_exact(&mut body).await?;
    } else {
        r.take(max_bytes as u64 + 1).read_to_end(&mut body).await?;
        if body.len() > max_bytes {
            return Err(too_big());
        }
    }
    Ok((status, location, body))
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

    #[test]
    fn locations() {
        let base = parse_url("https://github.com/o/r/releases/download/v1/x").unwrap();
        assert_eq!(resolve_location(&base, "https://cdn.example/a"), "https://cdn.example/a");
        assert_eq!(resolve_location(&base, "/b"), "https://github.com/b");
        assert_eq!(resolve_location(&base, "//cdn.example/c"), "https://cdn.example/c");
        let base = parse_url("http://127.0.0.1:8080/dir/f").unwrap();
        assert_eq!(resolve_location(&base, "g"), "http://127.0.0.1:8080/dir/g");
    }

    /// Serve canned responses keyed by request path.
    async fn serve(routes: Vec<(&'static str, Vec<u8>)>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_ascii_whitespace().nth(1).unwrap_or("").to_string();
                    let resp = routes
                        .iter()
                        .find(|(p, _)| *p == path)
                        .map(|(_, r)| r.clone())
                        .unwrap_or_else(|| b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec());
                    let _ = sock.write_all(&resp).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn download_variants() {
        let port = serve(vec![
            ("/redir", b"HTTP/1.1 302 Found\r\nLocation: /chunked\r\nContent-Length: 0\r\n\r\n".to_vec()),
            (
                "/chunked",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;x=y\r\n world\r\n0\r\n\r\n"
                    .to_vec(),
            ),
            ("/len", b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".to_vec()),
            ("/close", b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil-eof".to_vec()),
            ("/big", b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".to_vec()),
        ])
        .await;
        let base = format!("http://127.0.0.1:{port}");
        let t = Duration::from_secs(5);
        assert_eq!(download(&format!("{base}/redir"), 1024, t).await.unwrap(), b"hello world");
        assert_eq!(download(&format!("{base}/len"), 1024, t).await.unwrap(), b"abc");
        assert_eq!(download(&format!("{base}/close"), 1024, t).await.unwrap(), b"until-eof");
        assert!(download(&format!("{base}/big"), 10, t).await.is_err());
        assert!(download(&format!("{base}/missing"), 10, t).await.is_err());
    }
}
