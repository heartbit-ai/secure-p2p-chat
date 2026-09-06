//! Local and public network discovery helpers for advertise URLs.

use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

/// Best-effort local IPv4 discovery via UDP connect trick (no extra iface crate).
pub fn local_ipv4_addrs() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for probe in ["8.8.8.8:80", "1.1.1.1:80"] {
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
            if socket.connect(probe).is_ok() {
                if let Ok(local) = socket.local_addr() {
                    if let IpAddr::V4(v4) = local.ip() {
                        if !v4.is_loopback() && !v4.is_unspecified() && !out.contains(&v4) {
                            out.push(v4);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Build HTTP candidate base URLs for a listen port.
pub fn candidate_base_urls(port: u16, advertise_host: Option<&str>) -> Vec<String> {
    let mut urls = Vec::new();
    if let Some(host) = advertise_host.map(str::trim).filter(|h| !h.is_empty()) {
        let host = host
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/');
        if let Some((h, p)) = host.rsplit_once(':') {
            if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
                urls.push(format!("http://{h}:{p}"));
            } else {
                urls.push(format!("http://{host}:{port}"));
            }
        } else {
            urls.push(format!("http://{host}:{port}"));
        }
    }
    for ip in local_ipv4_addrs() {
        let url = format!("http://{ip}:{port}");
        if !urls.contains(&url) {
            urls.push(url);
        }
    }
    let loopback = format!("http://127.0.0.1:{port}");
    if !urls.contains(&loopback) {
        urls.push(loopback);
    }
    urls
}

/// Query a public STUN server for the reflexive IPv4 address (optional hint).
pub fn stun_public_ipv4(timeout: Duration) -> Option<Ipv4Addr> {
    const SERVER: &str = "stun.l.google.com:19302";
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    socket.set_write_timeout(Some(timeout)).ok()?;
    socket.connect(SERVER).ok()?;

    let mut req = [0u8; 20];
    req[0] = 0x00;
    req[1] = 0x01; // Binding Request
    req[4] = 0x21;
    req[5] = 0x12;
    req[6] = 0xa4;
    req[7] = 0x42; // magic cookie
    rand::thread_rng().fill_bytes(&mut req[8..20]);
    socket.send(&req).ok()?;

    let mut buf = [0u8; 512];
    let n = socket.recv(&mut buf).ok()?;
    parse_stun_xor_mapped_v4(&buf[..n])
}

fn parse_stun_xor_mapped_v4(msg: &[u8]) -> Option<Ipv4Addr> {
    if msg.len() < 20 {
        return None;
    }
    let magic = [0x21u8, 0x12, 0xa4, 0x42];
    let mut i = 20usize;
    while i + 4 <= msg.len() {
        let attr_type = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let attr_len = u16::from_be_bytes([msg[i + 2], msg[i + 3]]) as usize;
        let value_start = i + 4;
        let value_end = value_start + attr_len;
        if value_end > msg.len() {
            break;
        }
        if (attr_type == 0x0020 || attr_type == 0x0001) && attr_len >= 8 {
            let family = msg[value_start + 1];
            if family == 0x01 {
                let mut addr = [
                    msg[value_start + 4],
                    msg[value_start + 5],
                    msg[value_start + 6],
                    msg[value_start + 7],
                ];
                if attr_type == 0x0020 {
                    for (a, m) in addr.iter_mut().zip(magic.iter()) {
                        *a ^= *m;
                    }
                }
                return Some(Ipv4Addr::from(addr));
            }
        }
        let padded = (attr_len + 3) & !3;
        i = value_start + padded;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_urls_prefer_advertise_host() {
        let urls = candidate_base_urls(7420, Some("chat.example.com"));
        assert_eq!(urls[0], "http://chat.example.com:7420");
        assert!(urls.iter().any(|u| u.contains("127.0.0.1")));
    }

    #[test]
    fn advertise_host_may_include_port() {
        let urls = candidate_base_urls(7420, Some("203.0.113.10:9000"));
        assert_eq!(urls[0], "http://203.0.113.10:9000");
    }
}
