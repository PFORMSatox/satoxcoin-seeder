use crate::net::NetAddr;
use crate::serialize::{sha256d, write_varstr};
use crate::app_state;

pub const COMMAND_SIZE: usize = 12;
pub const MAX_SIZE: u32 = 0x02000000;

#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub magic: [u8; 4],
    pub command: [u8; COMMAND_SIZE],
    pub payload_size: u32,
    pub checksum: [u8; 4],
}

impl MessageHeader {
    pub fn new(command: &str, payload_size: u32) -> Self {
        let mut cmd = [0u8; COMMAND_SIZE];
        let bytes = command.as_bytes();
        let len = bytes.len().min(COMMAND_SIZE);
        cmd[..len].copy_from_slice(&bytes[..len]);
        MessageHeader {
            magic: app_state().message_start,
            command: cmd,
            payload_size,
            checksum: [0u8; 4],
        }
    }

    pub fn set_checksum(&mut self, payload: &[u8]) {
        let hash = sha256d(payload);
        self.checksum.copy_from_slice(&hash[..4]);
    }

    pub fn command_str(&self) -> String {
        let end = self
            .command
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(COMMAND_SIZE);
        String::from_utf8_lossy(&self.command[..end]).to_string()
    }

    pub fn is_valid(&self) -> bool {
        if self.magic != app_state().message_start {
            return false;
        }
        for &b in &self.command {
            if b != 0 && !(b.is_ascii_graphic() || b == b' ') {
                return false;
            }
        }
        self.payload_size <= MAX_SIZE
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.magic);
        buf.extend_from_slice(&self.command);
        buf.extend_from_slice(&self.payload_size.to_le_bytes());
        buf.extend_from_slice(&self.checksum);
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.len() < 24 {
            return Err("header too short");
        }
        let mut magic = [0u8; 4];
        let mut command = [0u8; COMMAND_SIZE];
        let mut checksum = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);
        command.copy_from_slice(&data[4..16]);
        let payload_size = u32::from_le_bytes(data[16..20].try_into().unwrap());
        checksum.copy_from_slice(&data[20..24]);
        Ok((
            MessageHeader {
                magic,
                command,
                payload_size,
                checksum,
            },
            24,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct Address {
    pub time: u32,
    pub services: u64,
    pub addr: NetAddr,
    pub port: u16,
}

impl Address {
    pub fn serialize(&self) -> Vec<u8> {
        let state = app_state();
        let mut buf = Vec::new();
        let include_time = (state.caddr_time_version == 0
            && state.init_proto_version != state.protocol_version)
            || state.protocol_version >= state.caddr_time_version;
        if include_time {
            buf.extend_from_slice(&self.time.to_le_bytes());
        }
        buf.extend_from_slice(&self.services.to_le_bytes());
        buf.extend_from_slice(self.addr.bytes());
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf
    }

    pub fn deserialize(
        data: &[u8],
        pos: &mut usize,
        version: u32,
        caddr_time_version: u32,
    ) -> Result<Self, &'static str> {
        let state = app_state();
        let mut time = 100000000;
        let include_time = (caddr_time_version == 0 && state.init_proto_version != version)
            || version >= caddr_time_version;
        if include_time {
            if *pos + 4 > data.len() {
                return Err("addr: unexpected end for time");
            }
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&data[*pos..*pos + 4]);
            time = u32::from_le_bytes(buf);
            *pos += 4;
        }
        if *pos + 8 > data.len() {
            return Err("addr: unexpected end for services");
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[*pos..*pos + 8]);
        let services = u64::from_le_bytes(buf);
        *pos += 8;
        if *pos + 16 > data.len() {
            return Err("addr: unexpected end for ip");
        }
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&data[*pos..*pos + 16]);
        *pos += 16;
        if *pos + 2 > data.len() {
            return Err("addr: unexpected end for port");
        }
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&data[*pos..*pos + 2]);
        let port = u16::from_be_bytes(buf);
        *pos += 2;
        Ok(Address {
            time,
            services,
            addr: NetAddr::from_bytes(&ip),
            port,
        })
    }
}

pub fn serialize_version_payload(
    proto_version: u32,
    services: u64,
    timestamp: i64,
    addr_recv: &Address,
    addr_from: &Address,
    nonce: u64,
    sub_version: &str,
    start_height: i32,
    relay: u8,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&proto_version.to_le_bytes());
    payload.extend_from_slice(&services.to_le_bytes());
    payload.extend_from_slice(&(timestamp as i64).to_le_bytes());
    payload.extend_from_slice(&addr_recv.serialize());
    payload.extend_from_slice(&addr_from.serialize());
    payload.extend_from_slice(&nonce.to_le_bytes());
    write_varstr(&mut payload, sub_version);
    payload.extend_from_slice(&start_height.to_le_bytes());
    payload.push(relay);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::init_app_state;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            let cfg = config::Config {
                protocol_version: 70028,
                init_proto_version: 209,
                min_peer_proto_version: 70025,
                caddr_time_version: 0,
                pch_message_start: [0x63, 0x56, 0x65, 0x65],
                wallet_port: 60777,
                explorer_url: None,
                second_explorer_url: None,
                explorer_requery_seconds: 600,
                block_count: 0,
                seeds: vec![],
                cf_domain: None,
                cf_domain_prefix: None,
                cf_api_token: None,
                cf_seed_dump: None,
                cf_max_seeds: None,
            };
            init_app_state(&cfg);
        });
    }

    #[test]
    fn test_message_header_new() {
        setup();
        let hdr = MessageHeader::new("version", 100);
        assert_eq!(hdr.magic, [0x63, 0x56, 0x65, 0x65]);
        assert_eq!(hdr.command_str(), "version");
        assert_eq!(hdr.payload_size, 100);
    }

    #[test]
    fn test_message_header_serialize_roundtrip() {
        setup();
        let mut hdr = MessageHeader::new("getaddr", 0);
        hdr.set_checksum(&[]);
        let bytes = hdr.serialize();
        assert_eq!(bytes.len(), 24);
        let (decoded, _) = MessageHeader::deserialize(&bytes).unwrap();
        assert_eq!(decoded.command_str(), "getaddr");
        assert_eq!(decoded.payload_size, 0);
    }

    #[test]
    fn test_message_header_checksum() {
        setup();
        let mut hdr = MessageHeader::new("ping", 8);
        hdr.set_checksum(&[0u8; 8]);
        let bytes = hdr.serialize();
        let (decoded, _) = MessageHeader::deserialize(&bytes).unwrap();
        assert_eq!(decoded.checksum, hdr.checksum);
    }

    #[test]
    fn test_message_header_valid() {
        setup();
        let mut hdr = MessageHeader::new("version", 100);
        hdr.set_checksum(&[0u8; 100]);
        assert!(hdr.is_valid());
    }

    #[test]
    fn test_message_header_invalid_wrong_magic() {
        setup();
        let mut hdr = MessageHeader::new("version", 0);
        hdr.magic = [0, 0, 0, 0];
        assert!(!hdr.is_valid());
    }

    #[test]
    fn test_message_header_invalid_too_large() {
        setup();
        let mut hdr = MessageHeader::new("version", 0x03000000);
        hdr.set_checksum(&[0u8; 1]);
        assert!(!hdr.is_valid());
    }

    #[test]
    fn test_message_header_deserialize_short() {
        setup();
        assert!(MessageHeader::deserialize(&[0u8; 12]).is_err());
    }

    #[test]
    fn test_address_serialize_minimal() {
        setup();
        let addr = Address {
            time: 100000000,
            services: 1,
            addr: NetAddr::from_bytes(&[
                0,0,0,0,0,0,0,0,0,0,0xff,0xff, 8,8,8,8
            ]),
            port: 60777,
        };
        let bytes = addr.serialize();
        // 4 time + 8 services + 16 ip + 2 port = 30
        assert!(bytes.len() == 26 || bytes.len() == 30);
    }

    #[test]
    fn test_address_deserialize_roundtrip() {
        setup();
        let addr = Address {
            time: 1234567,
            services: 9,
            addr: NetAddr::from_bytes(&[
                0,0,0,0,0,0,0,0,0,0,0xff,0xff, 1,2,3,4
            ]),
            port: 8333,
        };
        let bytes = addr.serialize();
        let mut pos = 0;
        let decoded = Address::deserialize(&bytes, &mut pos, 70028, 0).unwrap();
        assert_eq!(decoded.time, 1234567);
        assert_eq!(decoded.services, 9);
        assert_eq!(decoded.port, 8333);
    }

    #[test]
    fn test_version_payload_length() {
        setup();
        let recv = Address {
            time: 0, services: 1,
            addr: NetAddr::from_bytes(&[0; 16]),
            port: 60777,
        };
        let from = Address {
            time: 0, services: 1,
            addr: NetAddr::from_bytes(&[0; 16]),
            port: 60777,
        };
        let payload = serialize_version_payload(70028, 1, 1234567, &recv, &from, 42, "/satoxcoin-seeder:0.1/", 0, 1);
        // Should be 4+8+8 + addr_len + addr_len + 8 + varstr + 4 + 1
        assert!(payload.len() > 80);
    }
}
