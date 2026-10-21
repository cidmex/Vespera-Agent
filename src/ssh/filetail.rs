//! Tail a syslog-style auth log (`/var/log/auth.log`, `/var/log/secure`, ...),
//! surviving rotation and truncation, and resuming from a persisted offset.

use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::{LogLine, parser};

pub const CANDIDATES: &[&str] = &["/var/log/auth.log", "/var/log/secure", "/var/log/messages"];

pub fn detect() -> Option<PathBuf> {
    CANDIDATES.iter().map(PathBuf::from).find(|p| p.is_file())
}

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
struct State {
    path: String,
    inode: u64,
    offset: u64,
}

#[cfg(unix)]
fn inode(m: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.ino()
}

#[cfg(not(unix))]
fn inode(_m: &Metadata) -> u64 {
    0
}

struct Tail {
    path: PathBuf,
    file: Option<File>,
    inode: u64,
    pos: u64,
    partial: Vec<u8>,
}

impl Tail {
    /// Read whatever was appended since the last call, returning complete lines.
    fn poll(&mut self, out: &mut Vec<String>) {
        let meta = std::fs::metadata(&self.path).ok();
        if self.file.is_none() {
            let (Some(m), Ok(f)) = (meta.as_ref(), File::open(&self.path)) else { return };
            if inode(m) != self.inode {
                // Not the file our saved offset refers to: read it from the start.
                self.pos = 0;
            }
            self.inode = inode(m);
            self.file = Some(f);
        } else {
            // Drain the current handle first; after rotation it still points at the old file.
            self.read_available(out);
            if let Some(m) = meta.as_ref() {
                if inode(m) != self.inode {
                    if let Ok(f) = File::open(&self.path) {
                        self.inode = inode(m);
                        self.file = Some(f);
                        self.pos = 0;
                        self.partial.clear();
                    }
                } else if m.len() < self.pos {
                    // Truncated in place (copytruncate).
                    self.pos = 0;
                    self.partial.clear();
                }
            }
        }
        self.read_available(out);
    }

    fn read_available(&mut self, out: &mut Vec<String>) {
        let Some(f) = self.file.as_mut() else { return };
        if f.seek(SeekFrom::Start(self.pos)).is_err() {
            return;
        }
        let mut buf = Vec::new();
        let Ok(n) = f.take(4 << 20).read_to_end(&mut buf) else { return };
        if n == 0 {
            return;
        }
        self.pos += n as u64;
        self.partial.extend_from_slice(&buf);
        while let Some(i) = self.partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.partial.drain(..=i).collect();
            out.push(String::from_utf8_lossy(&line[..line.len() - 1]).into_owned());
        }
    }
}

pub async fn run(path: PathBuf, state_dir: PathBuf, tx: mpsc::Sender<LogLine>) {
    let state_path = state_dir.join("filetail.json");
    let saved: State =
        std::fs::read_to_string(&state_path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();

    let meta = std::fs::metadata(&path).ok();
    let cur_inode = meta.as_ref().map(inode).unwrap_or(0);
    let cur_len = meta.as_ref().map(|m| m.len()).unwrap_or(0);
    let path_str = path.to_string_lossy().into_owned();
    // Resume where we left off if it is still the same file, otherwise start at the end.
    let pos = if saved.path == path_str && saved.inode == cur_inode && saved.offset <= cur_len {
        saved.offset
    } else {
        cur_len
    };
    let mut tail = Tail { path: path.clone(), file: None, inode: cur_inode, pos, partial: Vec::new() };
    tracing::info!(path = %path.display(), "ssh monitor: tailing log file");

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut last_saved = saved;
    let mut since_save = 0u32;
    let mut lines = Vec::new();
    loop {
        tick.tick().await;
        tail.poll(&mut lines);
        for line in lines.drain(..) {
            if let Some(msg) = parser::syslog_message(&line) {
                let now = super::now_secs();
                // Trust the log's own timestamp unless it is clearly off (clock skew, odd format).
                let ts = parser::syslog_time(&line, now)
                    .filter(|t| (now - 7 * 86400..=now + 300).contains(t))
                    .unwrap_or(now);
                if tx.send(LogLine { ts, msg: msg.to_string() }).await.is_err() {
                    return;
                }
            }
        }
        since_save += 1;
        if since_save >= 5 {
            since_save = 0;
            let st = State { path: path_str.clone(), inode: tail.inode, offset: tail.pos };
            if st != last_saved {
                if let Ok(s) = serde_json::to_string(&st) {
                    let _ = std::fs::write(&state_path, s);
                }
                last_saved = st;
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn rotation_and_truncation() {
        let dir = std::env::temp_dir().join(format!("vespera-tail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("auth.log");
        std::fs::write(&p, "old line\n").unwrap();
        let m = std::fs::metadata(&p).unwrap();
        let mut t = Tail { path: p.clone(), file: None, inode: inode(&m), pos: m.len(), partial: Vec::new() };
        let mut out = Vec::new();
        t.poll(&mut out);
        assert!(out.is_empty());

        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"a\nb").unwrap();
        t.poll(&mut out);
        assert_eq!(out, vec!["a"]);
        f.write_all(b"c\n").unwrap();
        t.poll(&mut out);
        assert_eq!(out, vec!["a", "bc"]);
        out.clear();

        // Rotate: append to old, then create new file at the same path.
        f.write_all(b"last-old\n").unwrap();
        std::fs::rename(&p, dir.join("auth.log.1")).unwrap();
        std::fs::write(&p, "new1\n").unwrap();
        t.poll(&mut out);
        assert_eq!(out, vec!["last-old", "new1"]);
        out.clear();

        // Truncate in place.
        std::fs::write(&p, "").unwrap();
        t.poll(&mut out);
        std::fs::write(&p, "t1\n").unwrap();
        t.poll(&mut out);
        assert_eq!(out, vec!["t1"]);
    }
}
