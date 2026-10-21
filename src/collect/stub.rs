//! Development stand-in for non-Linux hosts. Produces plausible synthetic data
//! so the agent can be run against a local panel on macOS.

use anyhow::Result;
use vespera_proto::{BasicInfo, Report};

use super::{Filters, now_ms};

pub struct Collector {
    start: std::time::Instant,
    rx_total: u64,
    tx_total: u64,
}

const GIB: u64 = 1 << 30;

impl Collector {
    pub fn new(_filters: Filters) -> Result<Self> {
        Ok(Self { start: std::time::Instant::now(), rx_total: 0, tx_total: 0 })
    }

    pub fn basic_info(&mut self) -> BasicInfo {
        BasicInfo {
            cpu_name: "Dev CPU (synthetic)".into(),
            cpu_cores: 8,
            arch: std::env::consts::ARCH.into(),
            os: format!("{} (dev stub)", std::env::consts::OS),
            kernel: "0.0.0".into(),
            virtualization: "none".into(),
            mem_total: 16 * GIB,
            swap_total: 2 * GIB,
            disk_total: 256 * GIB,
            ipv4: None,
            ipv6: None,
            boot_time: (now_ms() / 1000).saturating_sub(self.start.elapsed().as_secs() + 3600),
        }
    }

    pub fn report(&mut self) -> Report {
        let t = self.start.elapsed().as_secs_f64();
        let wave = |p: f64, a: f64| (t / p).sin() * a;
        let rx = (2_000_000.0 + wave(37.0, 1_500_000.0) + fastrand::f64() * 300_000.0) as u64;
        let tx = (800_000.0 + wave(23.0, 600_000.0) + fastrand::f64() * 100_000.0) as u64;
        self.rx_total += rx;
        self.tx_total += tx;
        Report {
            ts_ms: now_ms(),
            cpu: (30.0 + wave(60.0, 20.0) + fastrand::f64() * 5.0) as f32,
            mem_used: (6.0 * GIB as f64 + wave(120.0, 1.0 * GIB as f64)) as u64,
            mem_total: 16 * GIB,
            swap_used: 256 << 20,
            swap_total: 2 * GIB,
            disk_used: 100 * GIB,
            disk_total: 256 * GIB,
            net_rx: rx,
            net_tx: tx,
            net_rx_total: self.rx_total,
            net_tx_total: self.tx_total,
            load1: (1.5 + wave(90.0, 1.0)) as f32,
            load5: 1.2,
            load15: 1.0,
            tcp: 120 + fastrand::u32(0..10),
            udp: 12,
            procs: 320,
            uptime: self.start.elapsed().as_secs() + 3600,
        }
    }
}
