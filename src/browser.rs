//! Open a verifier's return page in the browser that is already talking to it.
//!
//! A same-device sign-in finishes only in the browser that started it. That
//! browser holds the binding cookie. `xdg-open` follows the desktop default,
//! which is a different browser, and the return is refused there. The same
//! tab cannot be driven from outside the browser. A new tab in the browser
//! that already has a connection to the verifier's host and port is the
//! return the sign-in page is built for.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::process::Command;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Firefox,
    Chromium,
}

#[derive(Clone, Debug)]
struct Proc {
    pid: u32,
    ppid: u32,
    exe: String,
    args: Vec<String>,
    start: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Launch {
    program: String,
    args: Vec<String>,
}

pub fn open_return(url: &str) -> Result<(), String> {
    if let Some(launch) = caller_of(url) {
        return spawn(&launch.program, &launch.args);
    }
    spawn("xdg-open", &[url.to_string()])
}

/// Open a documentation page with the desktop browser.
///
/// A page that is not `https`, or that names a user or `localhost`, is refused
/// before any program is started. Verifier returns use `open_return`.
pub fn open_https(url: &str) -> Result<(), String> {
    if !https_page(url) {
        return Err("refused".to_string());
    }
    spawn("xdg-open", &[url.to_string()])
}

pub(crate) fn https_page(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    if rest.is_empty() || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    !host.is_empty() && !host.contains('@') && !host.eq_ignore_ascii_case("localhost")
}

fn caller_of(url: &str) -> Option<Launch> {
    let endpoint = endpoint_of(url)?;
    let peers = peers_of(&endpoint);
    if peers.is_empty() {
        return None;
    }
    choose(&process_table(), &peers, std::process::id(), url)
}

fn spawn(program: &str, args: &[String]) -> Result<(), String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|err| err.to_string())?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

fn choose(procs: &[Proc], peers: &[u32], self_pid: u32, url: &str) -> Option<Launch> {
    let by_pid: HashMap<u32, &Proc> = procs.iter().map(|proc| (proc.pid, proc)).collect();
    let mut counts: HashMap<u32, usize> = HashMap::new();
    for peer in peers {
        if let Some(main) = browser_main(&by_pid, *peer, self_pid) {
            *counts.entry(main.pid).or_insert(0) += 1;
        }
    }
    let (pid, _) = counts.into_iter().max_by(|left, right| {
        left.1.cmp(&right.1).then_with(|| {
            let left_start = by_pid.get(&left.0).map_or(u64::MAX, |proc| proc.start);
            let right_start = by_pid.get(&right.0).map_or(u64::MAX, |proc| proc.start);
            right_start.cmp(&left_start)
        })
    })?;
    let proc = by_pid.get(&pid)?;
    let family = family_of(&proc.exe)?;
    Some(launch_for(family, &proc.exe, url))
}

fn browser_main<'a>(procs: &HashMap<u32, &'a Proc>, start: u32, self_pid: u32) -> Option<&'a Proc> {
    let mut pid = start;
    let mut seen = std::collections::HashSet::new();
    let mut found = None;
    while pid != 0 && pid != self_pid && seen.insert(pid) {
        let proc = procs.get(&pid)?;
        if !is_helper(&proc.exe, &proc.args) && family_of(&proc.exe).is_some() {
            found = Some(*proc);
        }
        pid = proc.ppid;
    }
    found
}

fn launch_for(family: Family, exe: &str, url: &str) -> Launch {
    let args = match family {
        Family::Firefox => vec!["-new-tab".to_string(), url.to_string()],
        Family::Chromium => vec![url.to_string()],
    };
    Launch {
        program: exe.to_string(),
        args,
    }
}

fn family_of(exe: &str) -> Option<Family> {
    let name = Path::new(exe)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(exe)
        .to_ascii_lowercase();
    if name.contains("crash") {
        return None;
    }
    if name.contains("firefox") {
        return Some(Family::Firefox);
    }
    if name.contains("chrome")
        || name.contains("chromium")
        || name.contains("brave")
        || name.contains("msedge")
        || name.contains("vivaldi")
    {
        return Some(Family::Chromium);
    }
    None
}

fn is_helper(exe: &str, args: &[String]) -> bool {
    if family_of(exe).is_none() && exe.to_ascii_lowercase().contains("crash") {
        return true;
    }
    args.iter()
        .any(|arg| arg == "-contentproc" || arg.starts_with("--type=") || arg.contains("crashpad"))
}

fn endpoint_of(url: &str) -> Option<Vec<SocketAddr>> {
    let https = url.strip_prefix("https://");
    let http = url.strip_prefix("http://");
    let (rest, default_port) = if let Some(rest) = https {
        (rest, 443)
    } else {
        let rest = http?;
        (rest, 80)
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.is_empty() {
        return None;
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (host, rest) = inner.split_once(']')?;
        let port = rest
            .strip_prefix(':')
            .map_or(Some(default_port), |text| text.parse().ok())?;
        (host.to_string(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            (authority.to_string(), default_port)
        } else {
            (host.to_string(), port.parse().ok()?)
        }
    } else {
        (authority.to_string(), default_port)
    };
    if host.is_empty() {
        return None;
    }
    let mut addresses = Vec::new();
    if let Ok(ip) = host.parse::<IpAddr>() {
        addresses.push(SocketAddr::new(ip, port));
    } else if host.eq_ignore_ascii_case("localhost") {
        addresses.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        addresses.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port));
    } else {
        let queried = (host.as_str(), port).to_socket_addrs().ok()?;
        addresses.extend(queried);
    }
    if addresses.is_empty() {
        None
    } else {
        Some(addresses)
    }
}

fn peers_of(endpoints: &[SocketAddr]) -> Vec<u32> {
    let mut inodes = Vec::new();
    if let Ok(text) = fs::read_to_string("/proc/net/tcp") {
        inodes.extend(matching_inodes(&text, false, endpoints));
    }
    if let Ok(text) = fs::read_to_string("/proc/net/tcp6") {
        inodes.extend(matching_inodes(&text, true, endpoints));
    }
    if inodes.is_empty() {
        return Vec::new();
    }
    pids_holding(&inodes)
}

fn matching_inodes(text: &str, ipv6: bool, endpoints: &[SocketAddr]) -> Vec<u64> {
    let mut inodes = Vec::new();
    for line in text.lines().skip(1) {
        let mut parts = line.split_whitespace();
        let _slot = parts.next();
        let _local = parts.next();
        let Some(remote) = parts.next() else {
            continue;
        };
        let Some(state) = parts.next() else {
            continue;
        };
        if state != "01" {
            continue;
        }
        let Some(inode) = parts.nth(5) else {
            continue;
        };
        let Some(remote) = decode_address(remote, ipv6) else {
            continue;
        };
        if endpoints
            .iter()
            .any(|endpoint| same_socket(*endpoint, remote))
        {
            if let Ok(inode) = inode.parse() {
                inodes.push(inode);
            }
        }
    }
    inodes
}

fn same_socket(left: SocketAddr, right: SocketAddr) -> bool {
    left.port() == right.port() && left.ip() == right.ip()
}

fn decode_address(text: &str, ipv6: bool) -> Option<SocketAddr> {
    let (addr, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = if ipv6 {
        IpAddr::V6(decode_ipv6(addr)?)
    } else {
        IpAddr::V4(decode_ipv4(addr)?)
    };
    Some(SocketAddr::new(ip, port))
}

fn decode_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let word = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(word.to_le_bytes()))
}

fn decode_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for index in 0..4 {
        let word = u32::from_str_radix(&hex[index * 8..index * 8 + 8], 16).ok()?;
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

fn pids_holding(inodes: &[u64]) -> Vec<u32> {
    let mut peers = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return peers;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let Some(text) = target.to_str() else {
                continue;
            };
            let Some(inode) = text
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
            else {
                continue;
            };
            if inodes.iter().any(|one| one.to_string() == inode) {
                peers.push(pid);
                break;
            }
        }
    }
    peers
}

fn process_table() -> Vec<Proc> {
    let mut procs = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return procs;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Some((parent, start)) = read_stat(pid) else {
            continue;
        };
        let exe = fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let args = fs::read(format!("/proc/{pid}/cmdline"))
            .map(|bytes| {
                bytes
                    .split(|byte| *byte == 0)
                    .filter(|part| !part.is_empty())
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .collect()
            })
            .unwrap_or_default();
        procs.push(Proc {
            pid,
            ppid: parent,
            exe,
            args,
            start,
        });
    }
    procs
}

fn read_stat(pid: u32) -> Option<(u32, u64)> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat_ppid_start(&text)
}

fn stat_ppid_start(text: &str) -> Option<(u32, u64)> {
    let rest = text.rsplit_once(')')?.1.trim_start();
    let mut parts = rest.split_whitespace();
    let _state = parts.next()?;
    let ppid = parts.next()?.parse().ok()?;
    let start = parts.nth(17)?.parse().ok()?;
    Some((ppid, start))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, parent: u32, exe: &str, args: &[&str], start: u64) -> Proc {
        Proc {
            pid,
            ppid: parent,
            exe: exe.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            start,
        }
    }

    #[test]
    fn an_https_page_is_opened_and_other_urls_are_refused() {
        assert!(https_page("https://rcbj.github.io/oid4vc-wallet/"));
        assert!(https_page(
            "https://github.com/rcbj/oid4vc-wallet/blob/main/LICENSE"
        ));
        assert!(!https_page("http://rcbj.github.io/oid4vc-wallet/"));
        assert!(!https_page("https://"));
        assert!(!https_page("https://user@github.com/rcbj/oid4vc-wallet"));
        assert!(!https_page("https://localhost/oid4vc-wallet"));
        assert!(!https_page("https://rcbj.github.io/oid4vc-wallet/\n"));
        assert!(open_https("http://example.com").is_err());
    }

    #[test]
    fn tcp_tables_decode_loopback() {
        let v4 = decode_address("0100007F:1F91", false).unwrap();
        assert_eq!(v4, "127.0.0.1:8081".parse::<SocketAddr>().unwrap());
        let v6 = decode_address("00000000000000000000000001000000:1F91", true).unwrap();
        assert_eq!(v6, "[::1]:8081".parse::<SocketAddr>().unwrap());
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:A1B2 0100007F:1F91 01 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 20 0 0 10 -1\n\
   1: 0100007F:A1B3 0100007F:1F91 06 00000000:00000000 00:00000000 00000000     0        0 99 1 0000000000000000 20 0 0 10 -1\n";
        let want = vec!["127.0.0.1:8081".parse::<SocketAddr>().unwrap()];
        assert_eq!(matching_inodes(text, false, &want), vec![4242]);
    }

    #[test]
    fn a_renderer_resolves_to_its_browser_and_firefox_opens_a_new_tab() {
        let procs = vec![
            proc(1, 0, "/lib/systemd/systemd", &["systemd"], 1),
            proc(10, 1, "/opt/google/chrome/chrome", &["chrome"], 50),
            proc(
                11,
                10,
                "/opt/google/chrome/chrome",
                &["chrome", "--type=renderer"],
                80,
            ),
            proc(20, 1, "/usr/lib/firefox/firefox", &["firefox"], 40),
            proc(
                21,
                20,
                "/usr/lib/firefox/firefox-bin",
                &["firefox-bin", "-contentproc"],
                90,
            ),
            proc(
                30,
                1,
                "/home/user/.local/bin/oid4vc-wallet",
                &["oid4vc-wallet"],
                100,
            ),
        ];
        let chrome = choose(&procs, &[11], 30, "https://localhost:8081/back").unwrap();
        assert_eq!(chrome.program, "/opt/google/chrome/chrome");
        assert_eq!(chrome.args, vec!["https://localhost:8081/back".to_string()]);
        let firefox = choose(&procs, &[21], 30, "https://localhost:8081/back").unwrap();
        assert_eq!(firefox.program, "/usr/lib/firefox/firefox");
        assert_eq!(
            firefox.args,
            vec![
                "-new-tab".to_string(),
                "https://localhost:8081/back".to_string()
            ]
        );
        assert!(choose(&procs, &[30], 30, "https://localhost:8081/back").is_none());
    }

    #[test]
    fn the_browser_with_more_connections_is_the_caller() {
        let procs = vec![
            proc(10, 1, "/opt/google/chrome/chrome", &["chrome"], 10),
            proc(20, 1, "/usr/bin/firefox", &["firefox"], 5),
        ];
        let launch = choose(&procs, &[10, 10, 20], 1, "https://localhost:8081/back").unwrap();
        assert_eq!(launch.program, "/opt/google/chrome/chrome");
    }

    #[test]
    fn stat_keeps_a_name_that_contains_a_parenthesis() {
        let text = "12 (Web Content) S 9 12 12 0 -1 0 1 0 0 0 2 2 0 0 20 0 3 0 777 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        assert_eq!(stat_ppid_start(text), Some((9, 777)));
    }
}
