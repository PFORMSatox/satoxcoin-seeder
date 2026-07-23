use sha2::{Digest, Sha256};

/// SHA256(SHA256(data))
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(&h1);
    let mut result = [0u8; 32];
    result.copy_from_slice(&h2);
    result
}

/// Write a Bitcoin-style variable-length integer (compact size)
pub fn write_varint(buf: &mut Vec<u8>, val: u64) {
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// Read a Bitcoin-style variable-length integer
pub fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, &'static str> {
    if *pos >= data.len() {
        return Err("varint: unexpected end");
    }
    let prefix = data[*pos];
    *pos += 1;
    match prefix {
        0xff => {
            if *pos + 8 > data.len() {
                return Err("varint: unexpected end for u64");
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[*pos..*pos + 8]);
            *pos += 8;
            Ok(u64::from_le_bytes(buf))
        }
        0xfe => {
            if *pos + 4 > data.len() {
                return Err("varint: unexpected end for u32");
            }
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&data[*pos..*pos + 4]);
            *pos += 4;
            Ok(u64::from(u32::from_le_bytes(buf)))
        }
        0xfd => {
            if *pos + 2 > data.len() {
                return Err("varint: unexpected end for u16");
            }
            let mut buf = [0u8; 2];
            buf.copy_from_slice(&data[*pos..*pos + 2]);
            *pos += 2;
            Ok(u64::from(u16::from_le_bytes(buf)))
        }
        _ => Ok(u64::from(prefix)),
    }
}

/// Write a variable-length string (varint length prefix + data)
pub fn write_varstr(buf: &mut Vec<u8>, s: &str) {
    write_varint(buf, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

/// Read a variable-length string
pub fn read_varstr(data: &[u8], pos: &mut usize) -> Result<String, &'static str> {
    let len = read_varint(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err("varstr: unexpected end");
    }
    let s = String::from_utf8(data[*pos..*pos + len].to_vec())
        .map_err(|_| "varstr: invalid utf8")?;
    *pos += len;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_u8() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 0xfc);
        assert_eq!(buf, vec![0xfc]);
        let mut pos = 0;
        assert_eq!(read_varint(&buf, &mut pos).unwrap(), 0xfc);
    }

    #[test]
    fn test_varint_u16() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 0xfd);
        assert_eq!(buf.len(), 3);
        assert_eq!(buf[0], 0xfd);
        let mut pos = 0;
        assert_eq!(read_varint(&buf, &mut pos).unwrap(), 0xfd);
    }

    #[test]
    fn test_varint_u32() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 0x10000u64);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf[0], 0xfe);
        let mut pos = 0;
        assert_eq!(read_varint(&buf, &mut pos).unwrap(), 0x10000);
    }

    #[test]
    fn test_varint_u64() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 0x100000001u64);
        assert_eq!(buf.len(), 9);
        assert_eq!(buf[0], 0xff);
        let mut pos = 0;
        assert_eq!(read_varint(&buf, &mut pos).unwrap(), 0x100000001);
    }

    #[test]
    fn test_sha256d() {
        let data = b"hello";
        let hash = sha256d(data);
        assert_eq!(hex::encode(hash), "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50");
    }

    #[test]
    fn test_varint_zero() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 0);
        assert_eq!(buf, vec![0]);
        let mut pos = 0;
        assert_eq!(read_varint(&buf, &mut pos).unwrap(), 0);
    }

    #[test]
    fn test_varstr_roundtrip() {
        let mut buf = Vec::new();
        write_varstr(&mut buf, "/Satoshi:0.18.0/");
        let mut pos = 0;
        assert_eq!(read_varstr(&buf, &mut pos).unwrap(), "/Satoshi:0.18.0/");
    }

    #[test]
    fn test_varint_empty() {
        assert!(read_varint(&[], &mut 0).is_err());
    }
}
