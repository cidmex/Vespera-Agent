//! Allocation-light parsers for Linux procfs files.
//!
//! Parsers are pure functions over `&str` so they can be unit-tested on any OS
//! with fixture data.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// A procfs file kept open and re-read from offset 0 into a reused buffer.
pub struct ProcFile {
    file: File,
    buf: String,
}

impl ProcFile {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self { file: File::open(path)?, buf: String::with_capacity(4096) })
    }

    pub fn read(&mut self) -> io::Result<&str> {
        self.buf.clear();
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_to_string(&mut self.buf)?;
        Ok(&self.buf)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CpuTimes {
    pub total: u64,
    pub idle: u64,
}

/// Aggregate `cpu` line of `/proc/stat`.
pub fn parse_cpu_stat(s: &str) -> Option<CpuTimes> {
    let line = s.lines().find(|l| l.starts_with("cpu "))?;
    let mut total = 0u64;
    let mut idle = 0u64;
    // user nice system idle iowait irq softirq steal [guest guest_nice]
    // guest time is already accounted in user/nice, so only the first 8 count.
    for (i, v) in line.split_ascii_whitespace().skip(1).take(8).enumerate() {
        let v: u64 = v.parse().ok()?;
        total += v;
        if i == 3 || i == 4 {
            idle += v;
        }
    }
    Some(CpuTimes { total, idle })
}

pub fn cpu_usage(prev: CpuTimes, cur: CpuTimes) -> f32 {
    let dt = cur.total.saturating_sub(prev.total);
    if dt == 0 {
        return 0.0;
    }
    let di = cur.idle.saturating_sub(prev.idle).min(dt);
    ((dt - di) as f64 / dt as f64 * 100.0) as f32
}

/// `btime` (boot time, unix seconds) from `/proc/stat`.
pub fn parse_btime(s: &str) -> Option<u64> {
    s.lines().find_map(|l| l.strip_prefix("btime ")).and_then(|v| v.trim().parse().ok())
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct MemInfo {
    pub total: u64,
    pub used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
}

/// htop-style memory accounting:
/// `used = MemTotal - MemFree - Buffers - Cached - SReclaimable + Shmem`.
pub fn parse_meminfo(s: &str) -> MemInfo {
    let (mut total, mut free, mut buffers, mut cached, mut sreclaim, mut shmem) = (0u64, 0, 0, 0, 0, 0);
    let (mut swap_total, mut swap_free, mut swap_cached) = (0u64, 0, 0);
    for line in s.lines() {
        let Some((key, rest)) = line.split_once(':') else { continue };
        let slot = match key {
            "MemTotal" => &mut total,
            "MemFree" => &mut free,
            "Buffers" => &mut buffers,
            "Cached" => &mut cached,
            "SReclaimable" => &mut sreclaim,
            "Shmem" => &mut shmem,
            "SwapTotal" => &mut swap_total,
            "SwapFree" => &mut swap_free,
            "SwapCached" => &mut swap_cached,
            _ => continue,
        };
        *slot = rest.split_ascii_whitespace().next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0) * 1024;
    }
    let used = (total + shmem).saturating_sub(free + buffers + cached + sreclaim);
    let swap_used = swap_total.saturating_sub(swap_free + swap_cached);
    MemInfo { total, used: used.min(total), swap_total, swap_used }
}

/// Interfaces that are always ignored unless explicitly included.
pub const NIC_DEFAULT_EXCLUDE: &[&str] = &[
    "lo", "docker", "veth", "br-", "virbr", "vmbr", "cni", "flannel", "cali", "tap", "tun", "podman", "fwbr", "fwpr",
    "kube-", "lxcbr", "vnet", "dummy", "ifb", "wg-mgmt",
];

/// Sum of rx/tx bytes from `/proc/net/dev` for interfaces accepted by `allow`.
pub fn parse_net_dev(s: &str, mut allow: impl FnMut(&str) -> bool) -> (u64, u64) {
    let (mut rx, mut tx) = (0u64, 0u64);
    for line in s.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else { continue };
        let name = name.trim();
        if !allow(name) {
            continue;
        }
        let mut it = rest.split_ascii_whitespace();
        let r: u64 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let t: u64 = it.nth(7).and_then(|v| v.parse().ok()).unwrap_or(0);
        rx += r;
        tx += t;
    }
    (rx, tx)
}

pub fn parse_loadavg(s: &str) -> (f32, f32, f32) {
    let mut it = s.split_ascii_whitespace().map(|v| v.parse::<f32>().unwrap_or(0.0));
    (it.next().unwrap_or(0.0), it.next().unwrap_or(0.0), it.next().unwrap_or(0.0))
}

pub fn parse_uptime(s: &str) -> u64 {
    s.split_ascii_whitespace().next().and_then(|v| v.parse::<f64>().ok()).map(|v| v as u64).unwrap_or(0)
}

/// `(tcp, udp)` sockets in use from `/proc/net/sockstat` (+ `sockstat6`).
pub fn parse_sockstat(s: &str) -> (u32, u32) {
    let (mut tcp, mut udp) = (0u32, 0u32);
    for line in s.lines() {
        let Some((proto, rest)) = line.split_once(':') else { continue };
        let slot = match proto {
            "TCP" | "TCP6" => &mut tcp,
            "UDP" | "UDP6" => &mut udp,
            _ => continue,
        };
        let mut it = rest.split_ascii_whitespace();
        while let Some(k) = it.next() {
            let v: u32 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            // `inuse` covers established/listening sockets; `tw` adds TIME_WAIT.
            if k == "inuse" || k == "tw" {
                *slot += v;
            }
        }
    }
    (tcp, udp)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Mount {
    pub dev: String,
    pub mount_point: String,
    pub fstype: String,
    pub source: String,
}

fn unescape_octal(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let v = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `/proc/self/mountinfo`.
pub fn parse_mountinfo(s: &str) -> Vec<Mount> {
    let mut out = Vec::new();
    for line in s.lines() {
        let Some((left, right)) = line.split_once(" - ") else { continue };
        let l: Vec<&str> = left.split(' ').collect();
        let r: Vec<&str> = right.split(' ').collect();
        if l.len() < 5 || r.len() < 2 {
            continue;
        }
        out.push(Mount {
            dev: l[2].to_string(),
            mount_point: unescape_octal(l[4]),
            fstype: r[0].to_string(),
            source: unescape_octal(r[1]),
        });
    }
    out
}

const FS_EXCLUDE_PREFIX: &[&str] = &[
    "tmpfs",
    "devtmpfs",
    "udev",
    "nfs",
    "cifs",
    "smb",
    "vboxsf",
    "9p",
    "fuse",
    "overlay",
    "proc",
    "devpts",
    "sysfs",
    "cgroup",
    "mqueue",
    "hugetlbfs",
    "debugfs",
    "binfmt_misc",
    "securityfs",
    "nullfs",
    "tracefs",
    "configfs",
    "pstore",
    "bpf",
    "efivarfs",
    "autofs",
    "squashfs",
    "ramfs",
    "rpc_pipefs",
    "nsfs",
    "fusectl",
    "selinuxfs",
    "iso9660",
    "zram",
];

const MOUNT_EXCLUDE_PREFIX: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/dev",
    "/run",
    "/var/lib/containers",
    "/var/lib/docker",
    "/var/lib/kubelet",
    "/proc",
    "/sys",
    "/etc/resolv.conf",
    "/etc/host",
    "/nix/store",
    "/snap",
    "/boot/efi",
];

/// Select the mounts that count towards disk usage, de-duplicated by device.
pub fn select_disks(mounts: &[Mount], include: &[String]) -> Vec<Mount> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for m in mounts {
        let keep = if !include.is_empty() {
            include.iter().any(|p| p == &m.mount_point)
        } else {
            let fs_ok = m.fstype == "fuseblk" || !FS_EXCLUDE_PREFIX.iter().any(|p| m.fstype.starts_with(p));
            let mp_ok = m.mount_point == "/"
                || !MOUNT_EXCLUDE_PREFIX.iter().any(|p| {
                    m.mount_point == *p
                        || m.mount_point.starts_with(&format!("{p}/"))
                        || (p.ends_with("host") && m.mount_point.starts_with(p))
                });
            let src_ok = !m.source.starts_with("/dev/loop");
            fs_ok && mp_ok && src_ok
        };
        if !keep {
            continue;
        }
        // ZFS datasets of one pool share space: group by pool name.
        let key = if m.fstype == "zfs" {
            format!("zfs:{}", m.source.split('/').next().unwrap_or(&m.source))
        } else {
            m.dev.clone()
        };
        if seen.insert(key) {
            out.push(m.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu() {
        let a = parse_cpu_stat("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 2 3 4\nbtime 1700000000\n").unwrap();
        let b = parse_cpu_stat("cpu  150 0 150 900 0 0 0 0 0 0\n").unwrap();
        assert_eq!(a, CpuTimes { total: 1000, idle: 800 });
        assert!((cpu_usage(a, b) - 50.0).abs() < 0.01);
        assert_eq!(parse_btime("cpu 1\nbtime 1700000000\n"), Some(1_700_000_000));
    }

    #[test]
    fn meminfo() {
        let s = "MemTotal:       16000000 kB\nMemFree:         4000000 kB\nMemAvailable:    9000000 kB\nBuffers:          500000 kB\nCached:          4000000 kB\nSwapCached:            0 kB\nShmem:            200000 kB\nSReclaimable:     300000 kB\nSwapTotal:       2000000 kB\nSwapFree:        1500000 kB\n";
        let m = parse_meminfo(s);
        assert_eq!(m.total, 16_000_000 * 1024);
        assert_eq!(m.used, (16_000_000 - 4_000_000 - 500_000 - 4_000_000 - 300_000 + 200_000) * 1024);
        assert_eq!(m.swap_used, 500_000 * 1024);
    }

    #[test]
    fn netdev() {
        let s = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n  eth0: 5000 50 0 0 0 0 0 0 7000 70 0 0 0 0 0 0\ndocker0: 99 1 0 0 0 0 0 0 99 1 0 0 0 0 0 0\n";
        let (rx, tx) = parse_net_dev(s, |n| !NIC_DEFAULT_EXCLUDE.iter().any(|p| n.starts_with(p)));
        assert_eq!((rx, tx), (5000, 7000));
    }

    #[test]
    fn sockstat() {
        let v4 =
            "sockets: used 300\nTCP: inuse 12 orphan 0 tw 3 alloc 20 mem 4\nUDP: inuse 4 mem 1\nUDPLITE: inuse 0\n";
        let v6 = "TCP6: inuse 5\nUDP6: inuse 2\n";
        let (t1, u1) = parse_sockstat(v4);
        let (t2, u2) = parse_sockstat(v6);
        assert_eq!((t1 + t2, u1 + u2), (20, 6));
    }

    #[test]
    fn loadavg_uptime() {
        assert_eq!(parse_loadavg("0.50 0.25 0.10 1/200 1234\n"), (0.5, 0.25, 0.1));
        assert_eq!(parse_uptime("12345.67 99999.00\n"), 12345);
    }

    #[test]
    fn mounts() {
        let s = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
23 22 0:21 / /proc rw - proc proc rw
24 22 0:5 / /dev rw - devtmpfs udev rw
25 22 8:2 / /data\\040disk rw - xfs /dev/sda2 rw
26 22 8:1 /var/lib/docker /var/lib/docker rw - ext4 /dev/sda1 rw
27 22 0:40 / /mnt/pool rw - zfs tank rw
28 22 0:41 / /mnt/pool/sub rw - zfs tank/sub rw
29 22 7:0 / /snap/core rw - squashfs /dev/loop0 ro
30 22 0:50 / /run/user/0 rw - tmpfs tmpfs rw
31 22 8:1 / /mnt/bind rw - ext4 /dev/sda1 rw
";
        let all = parse_mountinfo(s);
        assert_eq!(all[3].mount_point, "/data disk");
        let d = select_disks(&all, &[]);
        let mps: Vec<_> = d.iter().map(|m| m.mount_point.as_str()).collect();
        assert_eq!(mps, vec!["/", "/data disk", "/mnt/pool"]);
        let d = select_disks(&all, &["/data disk".to_string()]);
        assert_eq!(d.len(), 1);
    }
}
