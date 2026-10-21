use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence};
    use tokio::sync::OnceCell;

    #[derive(Clone, Default)]
    pub struct Icmp {
        v4: Arc<OnceCell<Option<Client>>>,
        v6: Arc<OnceCell<Option<Client>>>,
    }

    impl Icmp {
        pub fn new() -> Self {
            Self::default()
        }

        async fn client(&self, v6: bool) -> Option<&Client> {
            let cell = if v6 { &self.v6 } else { &self.v4 };
            cell.get_or_init(|| async move {
                let cfg = if v6 { Config::builder().kind(ICMP::V6).build() } else { Config::default() };
                match Client::new(&cfg) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        tracing::warn!("icmp: cannot open socket (need root or ping_group_range): {e}");
                        None
                    }
                }
            })
            .await
            .as_ref()
        }

        pub async fn ping(&self, target: &str, seq: u16, timeout: Duration) -> Option<u32> {
            let ip = resolve(target).await?;
            let client = self.client(ip.is_ipv6()).await?;
            let mut pinger = client.pinger(ip, PingIdentifier(fastrand::u16(..))).await;
            pinger.timeout(timeout);
            let (_, rtt) = pinger.ping(PingSequence(seq), &[0u8; 32]).await.ok()?;
            Some(rtt.as_micros().min(u32::MAX as u128) as u32)
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    /// ICMP is only implemented on Linux; elsewhere fall back to a TCP/80 probe.
    #[derive(Clone, Default)]
    pub struct Icmp(Arc<()>);

    impl Icmp {
        pub fn new() -> Self {
            Self::default()
        }

        pub async fn ping(&self, target: &str, _seq: u16, timeout: Duration) -> Option<u32> {
            let ip = resolve(target).await?;
            let start = std::time::Instant::now();
            crate::net::connect(&ip.to_string(), 80, None, timeout).await.ok()?;
            Some(start.elapsed().as_micros() as u32)
        }
    }
}

pub use imp::Icmp;

async fn resolve(target: &str) -> Option<IpAddr> {
    let host = target.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse() {
        return Some(ip);
    }
    tokio::net::lookup_host((host, 0)).await.ok()?.next().map(|a| a.ip())
}
