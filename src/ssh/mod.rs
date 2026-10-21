//! SSH login monitoring: follow sshd logs, queue successful logins durably and
//! aggregate failed attempts into periodic summaries.

pub mod filetail;
pub mod journald;
pub mod parser;
pub mod queue;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, mpsc};
use vespera_proto::{SshEvent, SshFailSummary};

use parser::SshLine;
use queue::SshQueue;

pub const FAIL_WINDOW_SECS: u32 = 60;
const TOP_IPS: usize = 10;

pub struct LogLine {
    pub ts: i64,
    pub msg: String,
}

/// State shared between the watcher and the connection loop.
pub struct SshShared {
    pub queue: Mutex<SshQueue>,
    pub notify: Notify,
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

enum Source {
    Journald,
    File(PathBuf),
}

fn pick_source(spec: &str) -> Option<Source> {
    match spec {
        "journald" => Some(Source::Journald),
        "auto" | "" => {
            if journald::available() {
                Some(Source::Journald)
            } else {
                filetail::detect().map(Source::File)
            }
        }
        s => s.strip_prefix("file:").map(|p| Source::File(PathBuf::from(p))),
    }
}

/// Start SSH monitoring. Returns `None` when no log source could be found.
pub fn spawn(spec: &str, state_dir: &Path, fail_tx: mpsc::Sender<SshFailSummary>) -> Option<Arc<SshShared>> {
    let Some(source) = pick_source(spec) else {
        tracing::warn!(spec, "ssh monitor: no usable sshd log source found, SSH monitoring disabled");
        return None;
    };
    let shared = Arc::new(SshShared { queue: Mutex::new(SshQueue::open(state_dir)), notify: Notify::new() });
    let (tx, rx) = mpsc::channel::<LogLine>(1024);
    let dir = state_dir.to_path_buf();
    match source {
        Source::Journald => {
            tokio::spawn(journald::run(dir, tx));
        }
        Source::File(path) => {
            tokio::spawn(filetail::run(path, dir, tx));
        }
    }
    tokio::spawn(process(rx, shared.clone(), fail_tx));
    Some(shared)
}

async fn process(mut rx: mpsc::Receiver<LogLine>, shared: Arc<SshShared>, fail_tx: mpsc::Sender<SshFailSummary>) {
    let mut fails: HashMap<String, u32> = HashMap::new();
    let mut window_start = now_secs();
    let mut tick = tokio::time::interval(Duration::from_secs(FAIL_WINDOW_SECS as u64));
    tick.tick().await;
    loop {
        tokio::select! {
            line = rx.recv() => {
                let Some(line) = line else { return };
                match parser::parse_message(&line.msg) {
                    Some(SshLine::Accepted { user, ip, port, method, key_fp }) => {
                        tracing::info!(%user, %ip, port, %method, "ssh login");
                        let ev = SshEvent { seq: 0, ts: line.ts, user, ip, port, method, key_fp };
                        shared.queue.lock().unwrap().push(ev);
                        shared.notify.notify_one();
                    }
                    Some(SshLine::Failed { ip }) => {
                        *fails.entry(ip).or_default() += 1;
                    }
                    None => {}
                }
            }
            _ = tick.tick() => {
                if !fails.is_empty() {
                    let summary = summarize(window_start, &mut fails);
                    let _ = fail_tx.try_send(summary);
                }
                window_start = now_secs();
            }
        }
    }
}

fn summarize(window_start: i64, fails: &mut HashMap<String, u32>) -> SshFailSummary {
    let count = fails.values().sum();
    let mut top: Vec<(String, u32)> = fails.drain().collect();
    top.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top.truncate(TOP_IPS);
    SshFailSummary { window_start, window_secs: FAIL_WINDOW_SECS, count, top_ips: top }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_orders_and_truncates() {
        let mut m = HashMap::new();
        for i in 0..15u32 {
            m.insert(format!("10.0.0.{i}"), i + 1);
        }
        let s = summarize(100, &mut m);
        assert_eq!(s.count, (1..=15).sum::<u32>());
        assert_eq!(s.top_ips.len(), TOP_IPS);
        assert_eq!(s.top_ips[0], ("10.0.0.14".to_string(), 15));
        assert!(m.is_empty());
    }
}
