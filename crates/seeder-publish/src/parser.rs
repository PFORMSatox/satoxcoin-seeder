use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no seeds found in {0}")]
    NoSeeds(String),
    #[error("parse error: {0}")]
    Parse(String),
}

/// Parse a dnsseed.dump line: IP:port  fGood  lastSuccess  %(2h)...  blocks  svcs  version
/// Extracts IP addresses where port matches valid_port and fGood is 1
pub fn read_seed_dump<P: AsRef<Path>>(path: P, valid_port: u16) -> Result<Vec<String>, Error> {
    let file = File::open(path.as_ref())?;
    let reader = BufReader::new(file);
    let mut addresses = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let ip_port = parts[0];
        let fgood = parts[1];

        if fgood != "1" {
            continue;
        }

        let (ip, port) = parse_ip(ip_port)?;
        if port == valid_port {
            addresses.push(ip.to_string());
        }
    }

    if addresses.is_empty() {
        return Err(Error::NoSeeds(
            path.as_ref().to_string_lossy().to_string(),
        ));
    }

    Ok(addresses)
}

fn parse_ip(input: &str) -> Result<(&str, u16), Error> {
    if let Some(bracket_end) = input.find(']') {
        // IPv6: [addr]:port
        let ip = &input[1..bracket_end];
        let rest = &input[bracket_end + 1..];
        if let Some(port_str) = rest.strip_prefix(':') {
            let port = port_str
                .parse::<u16>()
                .map_err(|e| Error::Parse(format!("invalid port: {port_str}: {e}")))?;
            return Ok((ip, port));
        }
        return Err(Error::Parse(format!("invalid ipv6 format: {input}")));
    }

    // Bare IPv6 without brackets → not valid here
    if input.contains("::") {
        return Err(Error::Parse(format!("bare ipv6 without brackets: {input}")));
    }

    if let Some(colon) = input.rfind(':') {
        let ip = &input[..colon];
        let port_str = &input[colon + 1..];
        let port = port_str
            .parse::<u16>()
            .map_err(|e| Error::Parse(format!("invalid port: {port_str}: {e}")))?;
        return Ok((ip, port));
    }

    Err(Error::Parse(format!("no port found: {input}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        let (ip, port) = parse_ip("8.8.8.8:60777").unwrap();
        assert_eq!(ip, "8.8.8.8");
        assert_eq!(port, 60777);
    }

    #[test]
    fn test_parse_ipv6() {
        let (ip, port) = parse_ip("[::1]:8333").unwrap();
        assert_eq!(ip, "::1");
        assert_eq!(port, 8333);
    }

    #[test]
    fn test_parse_ipv6_full() {
        let (ip, port) = parse_ip("[2001:db8::1]:12345").unwrap();
        assert_eq!(ip, "2001:db8::1");
        assert_eq!(port, 12345);
    }

    #[test]
    fn test_parse_ip_no_port() {
        assert!(parse_ip("8.8.8.8").is_err());
    }

    #[test]
    fn test_parse_ipv6_no_bracket() {
        assert!(parse_ip("::1").is_err());
    }

    #[test]
    fn test_parse_ip_invalid_port() {
        assert!(parse_ip("8.8.8.8:abc").is_err());
    }

    #[test]
    fn test_read_seed_dump_valid_line() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_dump.txt");
        std::fs::write(&path, "1.2.3.4:60777 1 1234567890 100 0 70028 /Satoshi:0.18.0/ 0\n").unwrap();
        let addrs = read_seed_dump(&path, 60777).unwrap();
        assert_eq!(addrs, vec!["1.2.3.4"]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_read_seed_dump_filters_bad() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_dump_bad.txt");
        std::fs::write(&path, "1.2.3.4:60777 0 1234567890 100 0 70028\n").unwrap();
        assert!(read_seed_dump(&path, 60777).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_read_seed_dump_filters_port() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_dump_port.txt");
        std::fs::write(&path, "1.2.3.4:60777 1 1234567890 100 0 70028\n5.6.7.8:8333 1 1234567890 100 0 70028\n").unwrap();
        let addrs = read_seed_dump(&path, 60777).unwrap();
        assert_eq!(addrs, vec!["1.2.3.4"]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_read_seed_dump_skips_comments() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_dump_comment.txt");
        std::fs::write(&path, "# this is a comment\n1.2.3.4:60777 1 1234567890 100 0 70028\n").unwrap();
        let addrs = read_seed_dump(&path, 60777).unwrap();
        assert_eq!(addrs, vec!["1.2.3.4"]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_read_seed_dump_nonexistent() {
        let path = std::env::temp_dir().join("nonexistent_dump.txt");
        let result = read_seed_dump(&path, 60777);
        assert!(result.is_err());
    }
}
