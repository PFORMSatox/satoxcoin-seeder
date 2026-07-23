use std::collections::VecDeque;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use std::str::FromStr;
use crate::net::{NetAddr, Network, Service};
use crate::p2p::message::{
    serialize_version_payload, Address, MessageHeader,
};
use crate::serialize::{read_varint, sha256d};
use crate::app_state;

const BITCOIN_SEED_NONCE: u64 = 0x0539a019ca550825;

pub struct HandshakeResult {
    pub client_version: i32,
    pub client_sub_version: String,
    pub starting_height: i32,
    pub services: u64,
    pub addresses: Vec<Address>,
    pub ban: i64,
}

pub async fn test_node(
    service: &Service,
    current_block: i32,
    get_addr: bool,
) -> HandshakeResult {
    let socket_addr = match service.socket_addr() {
        Some(a) => a,
        None => {
            return HandshakeResult {
                client_version: 0,
                client_sub_version: String::new(),
                starting_height: 0,
                services: 0,
                addresses: Vec::new(),
                ban: 0,
            }
        }
    };

    let timeout_secs = if service.network() == Network::Tor {
        120u64
    } else {
        30
    };

    let stream = match timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(socket_addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            return HandshakeResult {
                client_version: 0,
                client_sub_version: String::new(),
                starting_height: 0,
                services: 0,
                addresses: Vec::new(),
                ban: 0,
            }
        }
    };

    let (mut reader, mut writer) = stream.into_split();

    let state = app_state();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let addr_recv = Address {
        time: 0,
        services: 0,
        addr: *service.addr(),
        port: service.port(),
    };
    let addr_from = Address {
        time: 0,
        services: 0,
        addr: NetAddr::from_str("0.0.0.0").unwrap(),
        port: 0,
    };

    let version_payload = serialize_version_payload(
        state.protocol_version,
        0,
        now,
        &addr_recv,
        &addr_from,
        BITCOIN_SEED_NONCE,
        &format!("/{}/", state.app_name),
        current_block,
        0,
    );

    let mut header = MessageHeader::new("version", version_payload.len() as u32);
    header.set_checksum(&version_payload);
    let mut send_buf = header.serialize();
    send_buf.extend_from_slice(&version_payload);

    if writer.write_all(&send_buf).await.is_err() {
        return HandshakeResult {
            client_version: 0,
            client_sub_version: String::new(),
            starting_height: 0,
            services: 0,
            addresses: Vec::new(),
            ban: 0,
        };
    }

    let mut read_buf = VecDeque::new();
    let mut tmp = [0u8; 4096];
    let mut remote_version = 0i32;
    let mut remote_subver = String::new();
    let mut remote_height = 0i32;
    let mut verack_received = false;
    let mut addresses = Vec::new();
    let mut ban = 0i64;

    let deadline = SystemTime::now() + Duration::from_secs(timeout_secs);

    loop {
        let remaining = deadline
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            break;
        }

        let n = match timeout(remaining, reader.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            _ => break,
        };
        read_buf.extend(&tmp[..n]);

        loop {
            let magic = state.message_start;
            let mut found = None;
            let buf_slice: &[u8] = read_buf.make_contiguous();
            for i in 0..buf_slice.len().saturating_sub(23) {
                if &buf_slice[i..i + 4] == &magic {
                    found = Some(i);
                    break;
                }
            }

            let start = match found {
                Some(s) => s,
                None => {
                    if read_buf.len() > 23 {
                        let tail = read_buf.split_off(read_buf.len() - 23);
                        read_buf = tail;
                    }
                    break;
                }
            };

            if start > 0 {
                read_buf.drain(..start);
            }

            if read_buf.len() < 24 {
                break;
            }

            let header_data: Vec<u8> = read_buf.iter().take(24).copied().collect();
            let (header, _) = match MessageHeader::deserialize(&header_data) {
                Ok(h) => h,
                Err(_) => {
                    read_buf.pop_front();
                    continue;
                }
            };

            if !header.is_valid() {
                ban = 100000;
                break;
            }

            let total_len = 24 + header.payload_size as usize;
            if read_buf.len() < total_len {
                break;
            }

            read_buf.drain(..24);

            let payload: Vec<u8> = read_buf.drain(..header.payload_size as usize).collect();

            let hash = sha256d(&payload);
            if hash[..4] != header.checksum {
                continue;
            }

            let cmd = header.command_str();
            let mut pos = 0;

            match cmd.as_str() {
                "version" => {
                    if payload.len() < 4 {
                        break;
                    }
                    let mut buf = [0u8; 4];
                    buf.copy_from_slice(&payload[..4]);
                    remote_version = i32::from_le_bytes(buf);
                    pos = 4;
                    pos += 8;
                    pos += 8;
                    pos += 26;
                    pos += 26;
                    pos += 8;
                    if let Ok(sv) = crate::serialize::read_varstr(&payload, &mut pos) {
                        remote_subver = sv;
                    }
                    if pos + 4 <= payload.len() {
                        let mut buf = [0u8; 4];
                        buf.copy_from_slice(&payload[pos..pos + 4]);
                        remote_height = i32::from_le_bytes(buf);
                    }

                    let verack_header = MessageHeader::new("verack", 0);
                    let vack = verack_header.serialize();
                    let _ = writer.write_all(&vack).await;

                    if get_addr {
                        let ga_header = MessageHeader::new("getaddr", 0);
                        let ga = ga_header.serialize();
                        let _ = writer.write_all(&ga).await;
                    }
                }
                "verack" => {
                    verack_received = true;
                }
                "addr" => {
                    if let Ok(count) = read_varint(&payload, &mut pos) {
                        for _ in 0..count.min(1000) {
                            match Address::deserialize(
                                &payload,
                                &mut pos,
                                remote_version as u32,
                                state.caddr_time_version,
                            ) {
                                Ok(addr) => addresses.push(addr),
                                Err(_) => break,
                            }
                        }
                    }
                    break;
                }
                _ => {}
            }
        }

        if ban > 0 {
            break;
        }
        if verack_received && !addresses.is_empty() {
            break;
        }
        if verack_received && !get_addr {
            break;
        }
    }

    HandshakeResult {
        client_version: remote_version,
        client_sub_version: remote_subver,
        starting_height: remote_height,
        services: 0,
        addresses,
        ban,
    }
}
