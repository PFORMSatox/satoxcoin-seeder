use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Copy)]
pub enum DnsType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Mx = 15,
    Aaaa = 28,
    Srv = 33,
    Any = 255,
}

impl DnsType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(DnsType::A),
            2 => Some(DnsType::Ns),
            5 => Some(DnsType::Cname),
            6 => Some(DnsType::Soa),
            15 => Some(DnsType::Mx),
            28 => Some(DnsType::Aaaa),
            33 => Some(DnsType::Srv),
            255 => Some(DnsType::Any),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DnsClass {
    In = 1,
    Any = 255,
}

impl DnsClass {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(DnsClass::In),
            255 => Some(DnsClass::Any),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Addr {
    pub v: u8,
    pub data: [u8; 16],
}

impl Addr {
    pub fn v4(a: [u8; 4]) -> Self {
        let mut data = [0u8; 16];
        data[..4].copy_from_slice(&a);
        Addr { v: 4, data }
    }

    pub fn v6(a: [u8; 16]) -> Self {
        Addr { v: 6, data: a }
    }
}

pub type IpCallback = Arc<dyn Fn(&str) -> Vec<Addr> + Send + Sync>;

pub struct DnsOpt {
    pub host: String,
    pub ns: String,
    pub mbox: String,
    pub addr: SocketAddr,
    pub datattl: u32,
    pub nsttl: u32,
    pub cb: IpCallback,
}

fn parse_name(data: &[u8], pos: &mut usize) -> Result<String, &'static str> {
    let mut name = String::new();
    let mut first = true;
    loop {
        if *pos >= data.len() {
            return Err("premature end");
        }
        let octet = data[*pos];
        *pos += 1;
        if octet == 0 {
            break;
        }
        if !first {
            name.push('.');
        }
        first = false;
        if (octet & 0xc0) == 0xc0 {
            if *pos >= data.len() {
                return Err("premature end in ref");
            }
            let ref_offset =
                (((octet as usize) & !0xc0) << 8) | data[*pos] as usize;
            *pos += 1;
            let mut ref_pos = ref_offset;
            let rest = parse_name(data, &mut ref_pos)?;
            name.push_str(&rest);
            return Ok(name);
        }
        if octet > 63 {
            return Err("label too long");
        }
        for _ in 0..octet {
            if *pos >= data.len() {
                return Err("premature end in label");
            }
            let c = data[*pos];
            *pos += 1;
            name.push(c as char);
        }
    }
    Ok(name)
}

fn write_name(buf: &mut Vec<u8>, name: &str) -> Result<usize, &'static str> {
    let start = buf.len();
    for part in name.split('.') {
        if part.len() > 63 {
            return Err("label too long");
        }
        buf.push(part.len() as u8);
        buf.extend_from_slice(part.as_bytes());
    }
    buf.push(0);
    Ok(buf.len() - start)
}

fn write_record_header(
    buf: &mut Vec<u8>,
    name: &str,
    typ: u16,
    cls: u16,
    ttl: u32,
) -> Result<(), &'static str> {
    write_name(buf, name)?;
    buf.extend_from_slice(&typ.to_be_bytes());
    buf.extend_from_slice(&cls.to_be_bytes());
    buf.extend_from_slice(&ttl.to_be_bytes());
    Ok(())
}

fn write_soa(
    buf: &mut Vec<u8>,
    name: &str,
    cls: u16,
    ttl: u32,
    mname: &str,
    rname: &str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
) -> Result<(), &'static str> {
    write_record_header(buf, name, 6, cls, ttl)?;
    let rdlen_pos = buf.len();
    buf.extend_from_slice(&[0u8; 2]); // placeholder rdlength
    write_name(buf, mname)?;
    write_name(buf, rname)?;
    buf.extend_from_slice(&serial.to_be_bytes());
    buf.extend_from_slice(&refresh.to_be_bytes());
    buf.extend_from_slice(&retry.to_be_bytes());
    buf.extend_from_slice(&expire.to_be_bytes());
    buf.extend_from_slice(&minimum.to_be_bytes());
    let rdlength = (buf.len() - rdlen_pos - 2) as u16;
    buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlength.to_be_bytes());
    Ok(())
}

fn write_a(
    buf: &mut Vec<u8>,
    name: &str,
    cls: u16,
    ttl: u32,
    addr: &Addr,
) -> Result<(), &'static str> {
    if addr.v != 4 {
        return Err("not v4");
    }
    write_record_header(buf, name, 1, cls, ttl)?;
    let rdlen_pos = buf.len();
    buf.extend_from_slice(&[0u16.to_be_bytes()].concat()); // rdlength placeholder
    buf.extend_from_slice(&addr.data[..4]);
    let rdlength = (buf.len() - rdlen_pos - 2) as u16;
    buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlength.to_be_bytes());
    Ok(())
}

fn write_aaaa(
    buf: &mut Vec<u8>,
    name: &str,
    cls: u16,
    ttl: u32,
    addr: &Addr,
) -> Result<(), &'static str> {
    if addr.v != 6 {
        return Err("not v6");
    }
    write_record_header(buf, name, 28, cls, ttl)?;
    let rdlen_pos = buf.len();
    buf.extend_from_slice(&[0u16.to_be_bytes()].concat());
    buf.extend_from_slice(&addr.data[..16]);
    let rdlength = (buf.len() - rdlen_pos - 2) as u16;
    buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlength.to_be_bytes());
    Ok(())
}

fn write_ns(
    buf: &mut Vec<u8>,
    name: &str,
    cls: u16,
    ttl: u32,
    ns: &str,
) -> Result<(), &'static str> {
    let before = buf.len();
    write_record_header(buf, name, 2, cls, ttl)?;
    buf.extend_from_slice(&[0u16.to_be_bytes()].concat());
    let rdlen_start = buf.len();
    write_name(buf, ns)?;
    let rdlength = (buf.len() - rdlen_start) as u16;
    let rlpos = before + 10;
    buf[rlpos..rlpos + 2].copy_from_slice(&rdlength.to_be_bytes());
    Ok(())
}

fn set_error_header(outbuf: &mut [u8], rcode: u8) {
    outbuf[3] = (outbuf[3] & 0xf0) | (rcode & 0x0f);
    outbuf[4..12].fill(0);
}

pub async fn run(opt: Arc<DnsOpt>) -> Result<(), String> {
    let socket = UdpSocket::bind(&opt.addr)
        .await
        .map_err(|e| format!("bind: {e}"))?;

    let mut inbuf = [0u8; 512];
    let mut outbuf = [0u8; 512];
    let mut _nrequests = 0u64;

    loop {
        let (len, src) = socket.recv_from(&mut inbuf).await.map_err(|e| format!("recv: {e}"))?;
        _nrequests += 1;

        if len < 12 {
            continue;
        }

        outbuf[..len.min(512)].copy_from_slice(&inbuf[..len.min(512)]);

        // Copy ID
        outbuf[0..2].copy_from_slice(&inbuf[0..2]);
        // Copy flags
        outbuf[2] = inbuf[2];
        outbuf[3] = inbuf[3];
        // Clear error
        outbuf[3] &= 0xf0;

        // Check QR (must be query)
        if inbuf[2] & 0x80 != 0 {
            set_error_header(&mut outbuf, 1);
            let _ = socket.send_to(&outbuf[..12], src).await;
            continue;
        }

        // Check opcode (must be standard)
        if (inbuf[2] >> 3) & 0x0f != 0 {
            set_error_header(&mut outbuf, 1);
            let _ = socket.send_to(&outbuf[..12], src).await;
            continue;
        }

        let nquestion = u16::from_be_bytes([inbuf[4], inbuf[5]]);
        if nquestion == 0 {
            set_error_header(&mut outbuf, 0);
            let _ = socket.send_to(&outbuf[..12], src).await;
            continue;
        }
        if nquestion > 1 {
            set_error_header(&mut outbuf, 4);
            let _ = socket.send_to(&outbuf[..12], src).await;
            continue;
        }

        let mut pos = 12usize;
        let _question_offset = pos;
        let name = match parse_name(&inbuf[..len], &mut pos) {
            Ok(n) => n,
            Err(_) => {
                set_error_header(&mut outbuf, 1);
                let _ = socket.send_to(&outbuf[..12], src).await;
                continue;
            }
        };

        if pos + 4 > len {
            set_error_header(&mut outbuf, 1);
            let _ = socket.send_to(&outbuf[..12], src).await;
            continue;
        }

        let qtype = u16::from_be_bytes([inbuf[pos], inbuf[pos + 1]]);
        let qclass = u16::from_be_bytes([inbuf[pos + 2], inbuf[pos + 3]]);
        pos += 4;

        let question_len = pos - 12;

        // Copy question to output
        outbuf[4..6].copy_from_slice(&[0u16.to_be_bytes()].concat());
        outbuf[6..12].fill(0);
        // Set QR
        outbuf[2] |= 0x80;

        let mut outpos = 12 + question_len;
        let outend = 512;

        let typ = qtype;
        let cls = qclass;

        // Check if the host matches
        let host_match = name == opt.host
            || name.ends_with(&format!(".{}", opt.host));

        if !host_match {
            set_error_header(&mut outbuf, 5);
            let _ = socket.send_to(&outbuf[..12], src).await;
            continue;
        }

        let mut answer_count: u16 = 0;
        let mut auth_count: u16 = 0;

        // Calculate max_auth_size
        let _max_auth_size = {
            let mut tmp = Vec::new();
            if let Ok(_) = write_ns(&mut tmp, "", cls, 0, &opt.ns) {}
            20 // rough estimate for SOA
        };

        // NS records
        if (typ == 2 || typ == 255) && (cls == 1 || cls == 255) {
            let mut tmp = Vec::new();
            if write_ns(&mut tmp, "", cls, opt.nsttl, &opt.ns).is_ok() {
                if outpos + tmp.len() < outend {
                    outbuf[outpos..outpos + tmp.len()].copy_from_slice(&tmp);
                    outpos += tmp.len();
                    answer_count += 1;
                }
            }
        }

        // SOA records
        if (typ == 6 || typ == 255) && (cls == 1 || cls == 255) && !opt.mbox.is_empty() {
            let serial = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
            let mut tmp = Vec::new();
            if write_soa(&mut tmp, "", cls, opt.nsttl, &opt.ns, &opt.mbox, serial, 604800, 86400, 2592000, 604800).is_ok() {
                if outpos + tmp.len() < outend {
                    outbuf[outpos..outpos + tmp.len()].copy_from_slice(&tmp);
                    outpos += tmp.len();
                    answer_count += 1;
                }
            }
        }

        // A/AAAA records
        if (typ == 1 || typ == 28 || typ == 255) && (cls == 1 || cls == 255) {
            let want_v4 = typ == 1 || typ == 255;
            let want_v6 = typ == 28 || typ == 255;

            let addrs = (opt.cb)(&name);
            for addr in &addrs {
                let mut tmp = Vec::new();
                let ok = if addr.v == 4 && want_v4 {
                    write_a(&mut tmp, "", cls, opt.datattl, addr)
                } else if addr.v == 6 && want_v6 {
                    write_aaaa(&mut tmp, "", cls, opt.datattl, addr)
                } else {
                    continue;
                };
                if ok.is_ok() && outpos + tmp.len() < outend {
                    outbuf[outpos..outpos + tmp.len()].copy_from_slice(&tmp);
                    outpos += tmp.len();
                    answer_count += 1;
                } else {
                    break;
                }
            }
        }

        // Authority section
        if answer_count > 0 {
            let mut tmp = Vec::new();
            if write_ns(&mut tmp, "", cls, opt.nsttl, &opt.ns).is_ok() {
                if outpos + tmp.len() < outend {
                    outbuf[outpos..outpos + tmp.len()].copy_from_slice(&tmp);
                    outpos += tmp.len();
                    auth_count += 1;
                }
            }
        } else if !opt.mbox.is_empty() {
            let serial = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
            let mut tmp = Vec::new();
            if write_soa(&mut tmp, "", cls, opt.nsttl, &opt.ns, &opt.mbox, serial, 604800, 86400, 2592000, 604800).is_ok() {
                if outpos + tmp.len() < outend {
                    outbuf[outpos..outpos + tmp.len()].copy_from_slice(&tmp);
                    outpos += tmp.len();
                    auth_count += 1;
                }
            }
        }

        // Set counts
        outbuf[4..6].copy_from_slice(&1u16.to_be_bytes());
        outbuf[6..8].copy_from_slice(&answer_count.to_be_bytes());
        outbuf[8..10].copy_from_slice(&auth_count.to_be_bytes());

        // Set AA
        outbuf[2] |= 0x04;

        let _ = socket.send_to(&outbuf[..outpos], src).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_type_from_u16() {
        assert_eq!(DnsType::from_u16(1).unwrap() as u16, 1);
        assert_eq!(DnsType::from_u16(28).unwrap() as u16, 28);
        assert!(DnsType::from_u16(99).is_none());
    }

    #[test]
    fn test_dns_class_from_u16() {
        assert_eq!(DnsClass::from_u16(1).unwrap() as u16, 1);
        assert!(DnsClass::from_u16(99).is_none());
    }

    #[test]
    fn test_addr_v4() {
        let a = Addr::v4([8, 8, 8, 8]);
        assert_eq!(a.v, 4);
        assert_eq!(a.data[..4], [8, 8, 8, 8]);
    }

    #[test]
    fn test_addr_v6() {
        let a = Addr::v6([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(a.v, 6);
        assert_eq!(a.data[0], 0x20);
        assert_eq!(a.data[15], 1);
    }

    #[test]
    fn test_parse_name_simple() {
        let bytes = &[3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
        let mut pos = 0;
        let name = parse_name(bytes, &mut pos).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(pos, bytes.len());
    }

    #[test]
    fn test_parse_name_root() {
        let bytes = &[0];
        let mut pos = 0;
        let name = parse_name(bytes, &mut pos).unwrap();
        assert_eq!(name, "");
    }

    #[test]
    fn test_parse_name_empty_buffer() {
        assert!(parse_name(&[], &mut 0).is_err());
    }

    #[test]
    fn test_parse_name_truncated_label() {
        // label length says 3 but only 1 byte follows
        let bytes = &[3, b'a'];
        assert!(parse_name(bytes, &mut 0).is_err());
    }

    #[test]
    fn test_parse_name_pointer() {
        // "abc" at offset 0 (null terminated), pointer to offset 0 at offset 4
        let bytes = &[3, b'a', b'b', b'c', 0, 0xc0, 0x00];
        let mut pos = 5;
        let name = parse_name(bytes, &mut pos).unwrap();
        assert_eq!(name, "abc");
    }

    #[test]
    fn test_write_name() {
        let mut buf = Vec::new();
        write_name(&mut buf, "www.example.com").unwrap();
        assert_eq!(buf, &[3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
    }

    #[test]
    fn test_write_name_label_too_long() {
        let mut buf = Vec::new();
        let long = "a".repeat(64);
        assert!(write_name(&mut buf, &long).is_err());
    }

    #[test]
    fn test_write_a() {
        let mut buf = Vec::new();
        let addr = Addr::v4([192, 168, 1, 1]);
        write_a(&mut buf, "test.local", 1, 3600, &addr).unwrap();
        // Encoded name "test.local": 4+1+4+1 = 11, + type/class/ttl + rdlen + 4 ip
        assert!(buf.len() > 20);
        assert!(buf.windows(4).any(|w| w == [192, 168, 1, 1]));
    }

    #[test]
    fn test_write_a_rejects_v6() {
        let mut buf = Vec::new();
        let addr = Addr::v6([0; 16]);
        assert!(write_a(&mut buf, "test", 1, 3600, &addr).is_err());
    }

    #[test]
    fn test_write_aaaa() {
        let mut buf = Vec::new();
        let addr = Addr::v6([0x20, 0x01, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        write_aaaa(&mut buf, "ipv6.test", 1, 3600, &addr).unwrap();
        // Name (10) + type/class/ttl (8) + rdlen (2) + IPv6 (16) = 36
        assert!(buf.len() >= 36);
        assert!(buf.windows(16).any(|w| w == [0x20, 0x01, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    }

    #[test]
    fn test_write_aaaa_rejects_v4() {
        let mut buf = Vec::new();
        let addr = Addr::v4([0; 4]);
        assert!(write_aaaa(&mut buf, "test", 1, 3600, &addr).is_err());
    }

    #[test]
    fn test_write_ns() {
        let mut buf = Vec::new();
        write_ns(&mut buf, "example.com", 1, 86400, "ns1.example.com").unwrap();
        assert!(!buf.is_empty());
        // Contains label "ns1" and "example" and "com"
        assert!(buf.windows(3).any(|w| w == b"ns1"));
    }

    #[test]
    fn test_write_soa() {
        let mut buf = Vec::new();
        write_soa(&mut buf, "example.com", 1, 3600, "ns1.example.com", "admin.example.com", 20240101, 604800, 86400, 2592000, 604800).unwrap();
        assert!(!buf.is_empty());
        // Contains mname label "ns1" and rname label "admin"
        assert!(buf.windows(3).any(|w| w == b"ns1"));
        assert!(buf.windows(5).any(|w| w == b"admin"));
        // Contains serial (20240101 = 0x0134C2E5)
        assert!(buf.windows(4).any(|w| w == 20240101u32.to_be_bytes()));
    }

    #[test]
    fn test_write_record_header() {
        let mut buf = Vec::new();
        write_record_header(&mut buf, "test", 1, 1, 300).unwrap();
        // question name + type(2) + class(2) + ttl(4) = variable + 8
        assert!(buf.len() > 8);
    }

    #[test]
    fn test_set_error_header() {
        let mut outbuf = [0xffu8; 512];
        outbuf[0..12].copy_from_slice(&[0u8; 12]);
        set_error_header(&mut outbuf, 3);
        assert_eq!(outbuf[3] & 0x0f, 3);
        assert_eq!(outbuf[4..12], [0, 0, 0, 0, 0, 0, 0, 0]);
    }
}
