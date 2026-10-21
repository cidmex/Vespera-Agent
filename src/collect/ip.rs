//! Public IP detection via Cloudflare's trace endpoint, addressed by IP literal
//! so it works without DNS and is pinned to one address family.

use std::time::Duration;

use crate::net::Family;
use crate::net::http::{get, parse_url};

const V4_ENDPOINTS: &[&str] = &["https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace"];
const V6_ENDPOINTS: &[&str] =
    &["https://[2606:4700:4700::1111]/cdn-cgi/trace", "https://[2606:4700:4700::1001]/cdn-cgi/trace"];

pub async fn lookup(family: Family) -> Option<String> {
    let list = match family {
        Family::V4 => V4_ENDPOINTS,
        Family::V6 => V6_ENDPOINTS,
    };
    for ep in list {
        let url = parse_url(ep)?;
        if let Ok(resp) = get(&url, Some(family), Duration::from_secs(5), true).await
            && resp.status == 200
            && let Some(ip) = parse_trace(&String::from_utf8_lossy(&resp.body))
        {
            let ok = match family {
                Family::V4 => ip.parse::<std::net::Ipv4Addr>().is_ok(),
                Family::V6 => ip.parse::<std::net::Ipv6Addr>().is_ok(),
            };
            if ok {
                return Some(ip);
            }
        }
    }
    None
}

fn parse_trace(body: &str) -> Option<String> {
    body.lines().find_map(|l| l.strip_prefix("ip=")).map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn trace() {
        assert_eq!(super::parse_trace("fl=1\nh=1.1.1.1\nip=203.0.113.5\nts=1\n").as_deref(), Some("203.0.113.5"));
    }
}
