use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[command(name = "vespera-agent", version = env!("VESPERA_AGENT_VERSION"), about = "Vespera monitoring agent")]
pub struct Config {
    /// Panel URL, e.g. https://status.example.com
    #[arg(short = 'e', long, env = "VESPERA_ENDPOINT")]
    pub endpoint: String,

    /// Node token from the panel
    #[arg(short = 't', long, env = "VESPERA_TOKEN", hide_env_values = true)]
    pub token: String,

    /// Report interval in seconds
    #[arg(short = 'i', long, env = "VESPERA_INTERVAL", default_value_t = 1.0)]
    pub interval: f64,

    /// Only count these NICs (comma separated, `*` and `?` wildcards)
    #[arg(long, env = "VESPERA_NIC_INCLUDE", value_delimiter = ',')]
    pub nic_include: Vec<String>,

    /// Ignore these NICs (comma separated, `*` and `?` wildcards)
    #[arg(long, env = "VESPERA_NIC_EXCLUDE", value_delimiter = ',')]
    pub nic_exclude: Vec<String>,

    /// Only count these mount points for disk usage (comma separated)
    #[arg(long, env = "VESPERA_MOUNT_INCLUDE", value_delimiter = ',')]
    pub mount_include: Vec<String>,

    /// Skip TLS certificate verification
    #[arg(long, env = "VESPERA_INSECURE")]
    pub insecure: bool,

    /// Where to read sshd logs: auto | journald | file:<path>
    #[arg(long, env = "VESPERA_SSH_SOURCE", default_value = "auto")]
    pub ssh_source: String,

    /// Disable SSH login monitoring
    #[arg(long, env = "VESPERA_DISABLE_SSH")]
    pub disable_ssh: bool,

    /// Directory for persistent agent state (SSH queue, log cursors)
    #[arg(long, env = "VESPERA_STATE_DIR", default_value = "/var/lib/vespera-agent")]
    pub state_dir: PathBuf,

    /// Report this IPv4 instead of detecting it
    #[arg(long, env = "VESPERA_IPV4")]
    pub ipv4: Option<String>,

    /// Report this IPv6 instead of detecting it
    #[arg(long, env = "VESPERA_IPV6")]
    pub ipv6: Option<String>,

    /// Do not query public IP endpoints
    #[arg(long, env = "VESPERA_NO_IP_LOOKUP")]
    pub no_ip_lookup: bool,

    /// Log level: error | warn | info | debug | trace
    #[arg(long, env = "VESPERA_LOG", default_value = "info")]
    pub log: String,
}

impl Config {
    pub fn report_interval(&self) -> Duration {
        Duration::from_secs_f64(self.interval.clamp(0.5, 300.0))
    }

    /// `wss://host/api/agent/ws` derived from the panel URL.
    pub fn ws_url(&self) -> String {
        let base = self.endpoint.trim_end_matches('/');
        let base = if let Some(rest) = base.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = base.strip_prefix("http://") {
            format!("ws://{rest}")
        } else if base.starts_with("ws://") || base.starts_with("wss://") {
            base.to_string()
        } else {
            format!("wss://{base}")
        };
        format!("{base}{}", vespera_proto::AGENT_WS_PATH)
    }
}

/// Minimal glob matcher supporting `*` and `?`.
pub fn glob_match(pattern: &str, s: &str) -> bool {
    let p = pattern.as_bytes();
    let s = s.as_bytes();
    let (mut pi, mut si) = (0, 0);
    let (mut star, mut mark) = (usize::MAX, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = pi;
            mark = si;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globbing() {
        assert!(glob_match("eth*", "eth0"));
        assert!(glob_match("en?0", "ens0"));
        assert!(!glob_match("eth*", "wlan0"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxbyy"));
    }

    #[test]
    fn ws_url() {
        let mut c = Config::parse_from(["x", "-e", "https://a.b/", "-t", "t"]);
        assert_eq!(c.ws_url(), "wss://a.b/api/agent/ws");
        c.endpoint = "http://1.2.3.4:25880".into();
        assert_eq!(c.ws_url(), "ws://1.2.3.4:25880/api/agent/ws");
        c.endpoint = "a.b".into();
        assert_eq!(c.ws_url(), "wss://a.b/api/agent/ws");
    }
}
