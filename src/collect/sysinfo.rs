//! Rarely-changing host facts: CPU model, OS, kernel, virtualization.

use std::path::Path;
use std::process::Command;

pub fn cpu_name() -> String {
    let s = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    parse_cpu_name(&s).unwrap_or_else(|| format!("{} CPU", std::env::consts::ARCH))
}

pub fn parse_cpu_name(cpuinfo: &str) -> Option<String> {
    for key in ["model name", "Hardware", "Processor", "cpu model", "Model", "uarch"] {
        for line in cpuinfo.lines() {
            if let Some((k, v)) = line.split_once(':')
                && k.trim() == key
            {
                let v = v.trim();
                if !v.is_empty() && v.parse::<u64>().is_err() {
                    return Some(v.split_ascii_whitespace().collect::<Vec<_>>().join(" "));
                }
            }
        }
    }
    None
}

pub fn cpu_cores() -> u32 {
    // SAFETY: sysconf is always safe to call.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n > 0 { n as u32 } else { std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1) }
}

pub fn os_name() -> String {
    for path in ["/etc/os-release", "/usr/lib/os-release"] {
        if let Ok(s) = std::fs::read_to_string(path)
            && let Some(name) = parse_os_release(&s)
        {
            return name;
        }
    }
    if Path::new("/etc/openwrt_release").exists() {
        return "OpenWrt".into();
    }
    std::env::consts::OS.into()
}

pub fn parse_os_release(s: &str) -> Option<String> {
    let get = |key: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix(key))
            .map(|v| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
    };
    let name = get("PRETTY_NAME=").or_else(|| get("NAME="))?;
    if Path::new("/usr/bin/pveversion").exists() {
        return Some(format!("Proxmox VE ({name})"));
    }
    Some(name)
}

pub fn kernel_version() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string()).unwrap_or_default()
}

pub fn virtualization() -> String {
    if let Ok(out) = Command::new("systemd-detect-virt").output() {
        let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !v.is_empty() {
            return v;
        }
    }
    if Path::new("/.dockerenv").exists() {
        return "docker".into();
    }
    if Path::new("/run/.containerenv").exists() {
        return "podman".into();
    }
    if let Ok(env) = std::fs::read("/proc/1/environ")
        && env.split(|b| *b == 0).any(|kv| kv.starts_with(b"container="))
    {
        return "container".into();
    }
    if let Ok(cg) = std::fs::read_to_string("/proc/1/cgroup") {
        for (needle, name) in [("docker", "docker"), ("kubepods", "kubernetes"), ("lxc", "lxc"), ("libpod", "podman")] {
            if cg.contains(needle) {
                return name.into();
            }
        }
    }
    cpuid_hypervisor().unwrap_or_else(|| "none".into())
}

#[cfg(target_arch = "x86_64")]
fn cpuid_hypervisor() -> Option<String> {
    use std::arch::x86_64::__cpuid;
    let leaf1 = __cpuid(1);
    if leaf1.ecx & (1 << 31) == 0 {
        return None;
    }
    let l = __cpuid(0x4000_0000);
    let mut v = Vec::with_capacity(12);
    for r in [l.ebx, l.ecx, l.edx] {
        v.extend_from_slice(&r.to_le_bytes());
    }
    let vendor = String::from_utf8_lossy(&v).trim_matches(char::from(0)).trim().to_string();
    Some(
        match vendor.as_str() {
            "KVMKVMKVM" => "kvm",
            "Microsoft Hv" => "microsoft",
            "VMwareVMware" => "vmware",
            "XenVMMXenVMM" => "xen",
            "VBoxVBoxVBox" => "oracle",
            "TCGTCGTCGTCG" => "qemu",
            "prl hyperv" => "parallels",
            "bhyve bhyve" => "bhyve",
            "ACRNACRNACRN" => "acrn",
            _ => "vm",
        }
        .into(),
    )
}

#[cfg(not(target_arch = "x86_64"))]
fn cpuid_hypervisor() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_names() {
        let x86 =
            "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R)   CPU E5-2680 v4 @ 2.40GHz\n";
        assert_eq!(parse_cpu_name(x86).unwrap(), "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz");
        let pi = "processor\t: 0\nBogoMIPS\t: 108.00\nCPU implementer\t: 0x41\n\nHardware\t: BCM2835\nModel\t\t: Raspberry Pi 4 Model B Rev 1.4\n";
        assert_eq!(parse_cpu_name(pi).unwrap(), "BCM2835");
        assert_eq!(parse_cpu_name("processor : 0\n"), None);
    }

    #[test]
    fn os_release() {
        assert_eq!(
            parse_os_release("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n").as_deref(),
            Some("Ubuntu 24.04.1 LTS")
        );
        assert_eq!(parse_os_release("NAME=Alpine\n").as_deref(), Some("Alpine"));
    }
}
