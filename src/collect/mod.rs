pub mod ip;
pub mod procfs;
pub mod sysinfo;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Collector;

#[cfg(not(target_os = "linux"))]
mod stub;
#[cfg(not(target_os = "linux"))]
pub use stub::Collector;

use crate::config::{Config, glob_match};

/// NIC / mount filters shared by the platform collectors.
#[derive(Debug, Clone)]
pub struct Filters {
    pub nic_include: Vec<String>,
    pub nic_exclude: Vec<String>,
    pub mount_include: Vec<String>,
}

impl Filters {
    pub fn from_config(cfg: &Config) -> Self {
        let clean = |v: &[String]| v.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        Self {
            nic_include: clean(&cfg.nic_include),
            nic_exclude: clean(&cfg.nic_exclude),
            mount_include: clean(&cfg.mount_include),
        }
    }

    pub fn nic_allowed(&self, name: &str) -> bool {
        if !self.nic_include.is_empty() {
            return self.nic_include.iter().any(|p| glob_match(p, name));
        }
        if procfs::NIC_DEFAULT_EXCLUDE.iter().any(|p| name.starts_with(p)) {
            return false;
        }
        !self.nic_exclude.iter().any(|p| glob_match(p, name))
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
