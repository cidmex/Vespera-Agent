pub mod http;
pub mod tls;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

/// Resolve `host:port` and connect, optionally restricted to one IP family.
pub async fn connect(host: &str, port: u16, family: Option<Family>, timeout: Duration) -> io::Result<TcpStream> {
    let fut = async {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await?
            .filter(|a| match family {
                Some(Family::V4) => a.is_ipv4(),
                Some(Family::V6) => a.is_ipv6(),
                None => true,
            })
            .collect();
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    };
    tokio::time::timeout(timeout, fut).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))?
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}
