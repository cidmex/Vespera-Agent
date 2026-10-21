//! Parsing of OpenSSH `sshd` log messages.
//!
//! Covers classic `sshd` as well as the `sshd-session` / `sshd-auth` processes
//! introduced by OpenSSH 9.8 / 10.0.

use std::sync::OnceLock;

use regex_lite::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshLine {
    Accepted {
        user: String,
        ip: String,
        port: u16,
        method: String,
        key_fp: Option<String>,
    },
    /// One failed authentication attempt from `ip`.
    Failed {
        ip: String,
    },
}

struct Patterns {
    syslog: Regex,
    accepted: Regex,
    failed: Regex,
    invalid: Regex,
    closed_auth: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        syslog: Regex::new(r"\bsshd(?:-session|-auth)?(?:\[\d+\])?: (.*)$").unwrap(),
        accepted: Regex::new(r"^Accepted (\S+) for (.+?) from (\S+) port (\d+)(?: ssh2)?(?:: (\S+) (\S+))?").unwrap(),
        failed: Regex::new(r"^Failed (\S+) for (invalid user )?(.+?) from (\S+) port (\d+)").unwrap(),
        invalid: Regex::new(r"^Invalid user (.*?) from (\S+)").unwrap(),
        closed_auth: Regex::new(r"^Connection closed by authenticating user (\S+) (\S+) port (\d+) \[preauth\]")
            .unwrap(),
    })
}

/// Extract the sshd message part from a syslog-formatted line
/// (`Oct 21 10:00:00 host sshd[123]: Accepted ...`).
pub fn syslog_message(line: &str) -> Option<&str> {
    let caps = patterns().syslog.captures(line)?;
    caps.get(1).map(|m| m.as_str())
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Timestamp of a syslog line, as unix seconds. Understands RFC 3339
/// (`2025-10-21T10:00:00.123+08:00`) and classic BSD (`Oct 21 10:00:00`,
/// local time, year inferred from `now`).
pub fn syslog_time(line: &str, now: i64) -> Option<i64> {
    let first = line.split_ascii_whitespace().next()?;
    if first.len() >= 19 && first.as_bytes()[4] == b'-' && first.as_bytes()[10] == b'T' {
        let n = |a: usize, b: usize| first.get(a..b)?.parse::<i64>().ok();
        let (y, mo, d, h, mi, s) = (n(0, 4)?, n(5, 7)?, n(8, 10)?, n(11, 13)?, n(14, 16)?, n(17, 19)?);
        let rest = first[19..].trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
        let offset = match rest {
            "" | "Z" => 0,
            r if r.len() == 6 && (r.starts_with('+') || r.starts_with('-')) => {
                let sign = if r.starts_with('-') { -1 } else { 1 };
                sign * (r[1..3].parse::<i64>().ok()? * 3600 + r[4..6].parse::<i64>().ok()? * 60)
            }
            _ => return None,
        };
        return Some(days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s - offset);
    }
    bsd_time(line.get(..15)?, now)
}

#[cfg(unix)]
fn bsd_time(s: &str, now: i64) -> Option<i64> {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let mon = MONTHS.iter().position(|m| s.starts_with(m))? as i32;
    let day: i32 = s.get(4..6)?.trim().parse().ok()?;
    let mut hms = s.get(7..15)?.split(':').map(|v| v.parse::<i32>().ok());
    let (h, mi, sec) = (hms.next()??, hms.next()??, hms.next()??);
    let year_of = |t: i64| {
        // `time_t` width differs between targets; let inference pick it.
        #[allow(clippy::useless_conversion)]
        let t = t.try_into().unwrap_or_default();
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: valid pointers to a time_t and an output tm.
        unsafe { libc::localtime_r(&t, &mut tm) };
        tm.tm_year
    };
    let mk = |year: i32| {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_year = year;
        tm.tm_mon = mon;
        tm.tm_mday = day;
        tm.tm_hour = h;
        tm.tm_min = mi;
        tm.tm_sec = sec;
        tm.tm_isdst = -1;
        // SAFETY: tm is fully initialised.
        unsafe { libc::mktime(&mut tm) as i64 }
    };
    let year = year_of(now);
    let t = mk(year);
    // A December line read in January belongs to last year.
    Some(if t > now + 86400 { mk(year - 1) } else { t })
}

#[cfg(not(unix))]
fn bsd_time(_s: &str, _now: i64) -> Option<i64> {
    None
}

/// Parse a bare sshd message (the part after `sshd[pid]: `).
pub fn parse_message(msg: &str) -> Option<SshLine> {
    let p = patterns();
    let msg = msg.trim_end();
    if msg.starts_with("Accepted ") {
        let c = p.accepted.captures(msg)?;
        let method = c.get(1)?.as_str().to_string();
        let key_fp = c.get(6).map(|m| m.as_str().to_string()).filter(|fp| fp.contains(':'));
        return Some(SshLine::Accepted {
            method,
            user: c.get(2)?.as_str().to_string(),
            ip: c.get(3)?.as_str().to_string(),
            port: c.get(4)?.as_str().parse().ok()?,
            key_fp,
        });
    }
    if msg.starts_with("Failed ") {
        let c = p.failed.captures(msg)?;
        // Invalid users are already counted once by the "Invalid user" line.
        if c.get(2).is_some() || c.get(1)?.as_str() == "none" {
            return None;
        }
        return Some(SshLine::Failed { ip: c.get(4)?.as_str().to_string() });
    }
    if msg.starts_with("Invalid user ") {
        let c = p.invalid.captures(msg)?;
        return Some(SshLine::Failed { ip: c.get(2)?.as_str().to_string() });
    }
    if msg.starts_with("Connection closed by authenticating user ") {
        let c = p.closed_auth.captures(msg)?;
        return Some(SshLine::Failed { ip: c.get(2)?.as_str().to_string() });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acc(user: &str, ip: &str, port: u16, method: &str, fp: Option<&str>) -> Option<SshLine> {
        Some(SshLine::Accepted {
            user: user.into(),
            ip: ip.into(),
            port,
            method: method.into(),
            key_fp: fp.map(Into::into),
        })
    }

    fn fail(ip: &str) -> Option<SshLine> {
        Some(SshLine::Failed { ip: ip.into() })
    }

    #[test]
    fn accepted_variants() {
        assert_eq!(
            parse_message("Accepted password for root from 203.0.113.5 port 52314 ssh2"),
            acc("root", "203.0.113.5", 52314, "password", None)
        );
        assert_eq!(
            parse_message("Accepted publickey for ubuntu from 2001:db8::1 port 50000 ssh2: ED25519 SHA256:AbC/dEf+123"),
            acc("ubuntu", "2001:db8::1", 50000, "publickey", Some("SHA256:AbC/dEf+123"))
        );
        assert_eq!(
            parse_message(
                "Accepted publickey for git from 10.0.0.2 port 40000 ssh2: RSA-CERT SHA256:xyz ID ci (serial 1) CA ED25519 SHA256:ca"
            ),
            acc("git", "10.0.0.2", 40000, "publickey", Some("SHA256:xyz"))
        );
        assert_eq!(
            parse_message("Accepted keyboard-interactive/pam for admin from 10.0.0.1 port 1234 ssh2"),
            acc("admin", "10.0.0.1", 1234, "keyboard-interactive/pam", None)
        );
        // Older RHEL style without the trailing protocol tag.
        assert_eq!(
            parse_message("Accepted gssapi-with-mic for bob from 192.168.1.9 port 2200"),
            acc("bob", "192.168.1.9", 2200, "gssapi-with-mic", None)
        );
    }

    #[test]
    fn failures() {
        assert_eq!(parse_message("Failed password for root from 1.2.3.4 port 22 ssh2"), fail("1.2.3.4"));
        assert_eq!(parse_message("Failed publickey for root from 1.2.3.4 port 22 ssh2: RSA SHA256:x"), fail("1.2.3.4"));
        assert_eq!(parse_message("Failed password for invalid user test from 1.2.3.4 port 22 ssh2"), None);
        assert_eq!(parse_message("Invalid user test from 5.6.7.8 port 5555"), fail("5.6.7.8"));
        assert_eq!(parse_message("Invalid user  from 5.6.7.8 port 5555"), fail("5.6.7.8"));
        assert_eq!(
            parse_message("Connection closed by authenticating user root 9.9.9.9 port 41000 [preauth]"),
            fail("9.9.9.9")
        );
        assert_eq!(parse_message("Disconnected from user root 1.2.3.4 port 22"), None);
        assert_eq!(parse_message("pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)"), None);
        assert_eq!(parse_message("Server listening on 0.0.0.0 port 22."), None);
    }

    #[test]
    fn timestamps() {
        let now = 1_792_585_000; // 2026-10-21
        assert_eq!(syslog_time("2026-10-21T10:00:00.123456+08:00 host sshd[1]: x", now), Some(1_792_548_000));
        assert_eq!(syslog_time("2026-10-21T02:00:00Z host sshd[1]: x", now), Some(1_792_548_000));
        assert_eq!(syslog_time("1970-01-01T00:00:00Z x", now), Some(0));
        // BSD format resolves in local time; only check it lands within a day of now.
        let t = syslog_time("Oct 21 10:00:00 host sshd[1]: x", now).unwrap();
        assert!((t - now).abs() < 2 * 86400, "{t}");
        let t = syslog_time("Dec 31 23:59:59 host sshd[1]: x", now).unwrap();
        assert!(t < now, "December line must resolve to the past: {t}");
        assert_eq!(syslog_time("garbage", now), None);
    }

    #[test]
    fn syslog_lines() {
        let deb = "Oct 21 10:00:00 web1 sshd[1234]: Accepted password for root from 1.1.1.1 port 1 ssh2";
        let iso = "2025-10-21T10:00:00.123456+08:00 web1 sshd-session[99]: Accepted publickey for a from ::1 port 2 ssh2: ED25519 SHA256:k";
        let alpine = "Oct 21 10:00:00 alpine auth.info sshd[2000]: Invalid user x from 3.3.3.3 port 9";
        let other = "Oct 21 10:00:00 web1 sudo: root : TTY=pts/0 ; COMMAND=/bin/ls";
        assert_eq!(parse_message(syslog_message(deb).unwrap()), acc("root", "1.1.1.1", 1, "password", None));
        assert_eq!(parse_message(syslog_message(iso).unwrap()), acc("a", "::1", 2, "publickey", Some("SHA256:k")));
        assert_eq!(parse_message(syslog_message(alpine).unwrap()), fail("3.3.3.3"));
        assert_eq!(syslog_message(other), None);
    }
}
