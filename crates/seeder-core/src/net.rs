use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

const PCH_IPV4_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
const PCH_ONION: [u8; 6] = [0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43];
const PCH_GARLIC: [u8; 6] = [0xfd, 0x60, 0xdb, 0x4d, 0xdd, 0xb5];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Network {
    Ipv4,
    Ipv6,
    Tor,
    I2p,
    Unroutable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetAddr {
    ip: [u8; 16],
}

impl NetAddr {
    pub fn from_ipv4(addr: Ipv4Addr) -> Self {
        let mut ip = [0u8; 16];
        ip[..12].copy_from_slice(&PCH_IPV4_PREFIX);
        ip[12..].copy_from_slice(&addr.octets());
        NetAddr { ip }
    }

    pub fn from_ipv6(addr: Ipv6Addr) -> Self {
        NetAddr { ip: addr.octets() }
    }

    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        NetAddr { ip: *bytes }
    }

    fn is_ipv4(&self) -> bool {
        self.ip[..12] == PCH_IPV4_PREFIX
    }

    fn is_tor(&self) -> bool {
        self.ip[..6] == PCH_ONION
    }

    fn is_i2p(&self) -> bool {
        self.ip[..6] == PCH_GARLIC
    }

    fn is_rfc1918(&self) -> bool {
        self.is_ipv4()
            && (self.byte(3) == 10
                || (self.byte(3) == 192 && self.byte(2) == 168)
                || (self.byte(3) == 172 && (16..=31).contains(&self.byte(2))))
    }

    fn is_local(&self) -> bool {
        if self.is_ipv4() && (self.byte(3) == 127 || self.byte(3) == 0) {
            return true;
        }
        self.ip == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    }

    fn is_rfc3849(&self) -> bool {
        self.ip[..4] == [0x20, 0x01, 0x0d, 0xb8]
    }

    fn is_reserved(&self) -> bool {
        self.is_ipv4() && self.byte(3) >= 240
    }

    fn byte(&self, n: usize) -> u8 {
        self.ip[15 - n]
    }

    pub fn is_valid(&self) -> bool {
        if self.ip[..9] == PCH_IPV4_PREFIX[3..] {
            return false;
        }
        if self.ip == [0u8; 16] {
            return false;
        }
        if self.is_rfc3849() {
            return false;
        }
        if self.is_ipv4() {
            let last4: [u8; 4] = self.ip[12..].try_into().unwrap();
            if last4 == Ipv4Addr::BROADCAST.octets() || last4 == Ipv4Addr::UNSPECIFIED.octets() {
                return false;
            }
        }
        true
    }

    pub fn is_routable(&self) -> bool {
        self.is_valid()
            && !(self.is_reserved()
                || self.is_rfc1918()
                || self.ip[12..] == [169, 254, 0, 0]
                || self.is_local()
                || self.is_rfc3849())
    }

    pub fn network(&self) -> Network {
        if !self.is_routable() {
            return Network::Unroutable;
        }
        if self.is_ipv4() {
            return Network::Ipv4;
        }
        if self.is_tor() {
            return Network::Tor;
        }
        if self.is_i2p() {
            return Network::I2p;
        }
        Network::Ipv6
    }

    pub fn to_ipv4_addr(&self) -> Option<Ipv4Addr> {
        if self.is_ipv4() {
            Some(Ipv4Addr::new(self.ip[12], self.ip[13], self.ip[14], self.ip[15]))
        } else {
            None
        }
    }

    pub fn to_ipv6_addr(&self) -> Option<Ipv6Addr> {
        if self.is_ipv4() || self.is_tor() || self.is_i2p() {
            return None;
        }
        Some(Ipv6Addr::from(self.ip))
    }

    pub fn to_ip_addr(&self) -> Option<IpAddr> {
        self.to_ipv4_addr().map(IpAddr::V4).or_else(|| self.to_ipv6_addr().map(IpAddr::V6))
    }

    pub fn bytes(&self) -> &[u8; 16] {
        &self.ip
    }
}

impl FromStr for NetAddr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(v4) = Ipv4Addr::from_str(s) {
            return Ok(NetAddr::from_ipv4(v4));
        }
        if let Ok(v6) = Ipv6Addr::from_str(s) {
            return Ok(NetAddr::from_ipv6(v6));
        }
        Err(format!("invalid address: {s}"))
    }
}

impl std::fmt::Display for NetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ip) = self.to_ip_addr() {
            write!(f, "{ip}")
        } else if self.is_tor() {
            let data = &self.ip[6..];
            let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, data);
            write!(f, "{encoded}.onion")
        } else if self.is_i2p() {
            let data = &self.ip[6..];
            let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, data);
            write!(f, "{encoded}.b32.i2p")
        } else {
            write!(f, "NetAddr({:02x?})", self.ip)
        }
    }
}

impl PartialOrd for NetAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.ip.cmp(&other.ip))
    }
}

impl Ord for NetAddr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ip.cmp(&other.ip)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Service {
    addr: NetAddr,
    port: u16,
}

impl Service {
    pub fn new(addr: NetAddr, port: u16) -> Self {
        Service { addr, port }
    }

    pub fn addr(&self) -> &NetAddr {
        &self.addr
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn network(&self) -> Network {
        self.addr.network()
    }

    pub fn is_routable(&self) -> bool {
        self.addr.is_routable()
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.addr.to_ip_addr().map(|ip| SocketAddr::new(ip, self.port))
    }

    pub fn to_string_ip(&self) -> String {
        self.addr.to_string()
    }

    pub fn to_string_ip_port(&self) -> String {
        let ip_str = self.addr.to_string();
        if self.addr.is_ipv4() {
            format!("{ip_str}:{}", self.port)
        } else {
            format!("[{ip_str}]:{}", self.port)
        }
    }
}

impl PartialOrd for Service {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.addr.cmp(&other.addr).then(self.port.cmp(&other.port)))
    }
}

impl Ord for Service {
    fn cmp(&self, other: &Self) -> Ordering {
        self.addr
            .cmp(&other.addr)
            .then(self.port.cmp(&other.port))
    }
}

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_ip_port())
    }
}

pub fn split_host_port(input: &str) -> (String, Option<u16>) {
    let input = input.trim();
    // Handle [ipv6]:port
    if input.starts_with('[') {
        if let Some(bracket_end) = input.find(']') {
            let host = input[1..bracket_end].to_string();
            if let Some(colon_pos) = input[bracket_end + 1..].find(':') {
                let port_str = &input[bracket_end + 1 + colon_pos + 1..];
                if let Ok(port) = port_str.parse::<u16>() {
                    return (host, Some(port));
                }
            }
            return (host, None);
        }
    }
    // Try ipv4:port or host:port
    if let Some(colon_pos) = input.rfind(':') {
        let host = &input[..colon_pos];
        let port_str = &input[colon_pos + 1..];
        // Only treat as port if the part after last colon is numeric
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), Some(port));
        }
    }
    (input.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_net_addr_ipv4() {
        let addr = NetAddr::from_str("1.2.3.4").unwrap();
        assert!(addr.is_ipv4());
        assert!(addr.is_valid());
        assert!(addr.is_routable());
        assert_eq!(addr.to_string(), "1.2.3.4");
    }

    #[test]
    fn test_net_addr_ipv6() {
        let addr = NetAddr::from_str("::1").unwrap();
        assert!(!addr.is_ipv4());
        assert!(!addr.is_routable());
    }

    #[test]
    fn test_net_addr_local() {
        assert!(!NetAddr::from_str("127.0.0.1").unwrap().is_routable());
    }

    #[test]
    fn test_net_addr_rfc1918() {
        assert!(!NetAddr::from_str("10.0.0.1").unwrap().is_routable());
        assert!(!NetAddr::from_str("192.168.1.1").unwrap().is_routable());
    }

    #[test]
    fn test_net_addr_routable() {
        let addr = NetAddr::from_str("8.8.8.8").unwrap();
        assert!(addr.is_routable());
    }

    #[test]
    fn test_net_addr_invalid() {
        assert!(!NetAddr::from_str("0.0.0.0").unwrap().is_valid());
    }

    #[test]
    fn test_net_addr_broadcast() {
        assert!(!NetAddr::from_str("255.255.255.255").unwrap().is_valid());
    }

    #[test]
    fn test_service_strings() {
        let s = Service::new(NetAddr::from_str("1.2.3.4").unwrap(), 60777);
        assert_eq!(s.to_string_ip_port(), "1.2.3.4:60777");
        assert_eq!(s.port(), 60777);
    }

    #[test]
    fn test_service_ordering() {
        let a = Service::new(NetAddr::from_str("1.1.1.1").unwrap(), 80);
        let b = Service::new(NetAddr::from_str("2.2.2.2").unwrap(), 80);
        assert!(a < b);
    }

    #[test]
    fn test_split_host_port_ipv4() {
        let (h, p) = split_host_port("1.2.3.4:60777");
        assert_eq!(h, "1.2.3.4"); assert_eq!(p, Some(60777));
    }

    #[test]
    fn test_split_host_port_ipv6() {
        let (h, p) = split_host_port("[::1]:60777");
        assert_eq!(h, "::1"); assert_eq!(p, Some(60777));
    }

    #[test]
    fn test_split_host_port_none() {
        let (h, p) = split_host_port("1.2.3.4");
        assert_eq!(h, "1.2.3.4"); assert_eq!(p, None);
    }

    #[test]
    fn test_ipv4_bytes_roundtrip() {
        let addr = NetAddr::from_ipv4(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(addr.to_ipv4_addr().unwrap(), Ipv4Addr::new(8, 8, 8, 8));
    }

    #[test]
    fn test_net_eq() {
        let a = NetAddr::from_str("1.2.3.4").unwrap();
        let b = NetAddr::from_str("1.2.3.4").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_net_ord() {
        let a = NetAddr::from_str("1.1.1.1").unwrap();
        let b = NetAddr::from_str("2.2.2.2").unwrap();
        assert!(a < b);
    }
}

pub fn lookup_host(host: &str) -> Result<Vec<NetAddr>, String> {
    if let Ok(addr) = NetAddr::from_str(host) {
        return Ok(vec![addr]);
    }
    let ips = tokio::task::block_in_place(|| {
        std::net::ToSocketAddrs::to_socket_addrs(host)
            .map_err(|e| format!("dns lookup failed: {e}"))
    })?;
    let mut result = Vec::new();
    for addr in ips {
        match addr {
            SocketAddr::V4(v4) => result.push(NetAddr::from_ipv4(*v4.ip())),
            SocketAddr::V6(v6) => result.push(NetAddr::from_ipv6(*v6.ip())),
        }
    }
    Ok(result)
}
