use std::path::Path;

#[derive(Debug, Clone)]
pub struct Config {
    pub protocol_version: u32,
    pub init_proto_version: u32,
    pub min_peer_proto_version: u32,
    pub caddr_time_version: u32,
    pub pch_message_start: [u8; 4],
    pub wallet_port: u16,
    pub explorer_url: Option<String>,
    pub second_explorer_url: Option<String>,
    pub explorer_requery_seconds: u64,
    pub block_count: i32,
    pub seeds: Vec<String>,
    pub cf_domain: Option<String>,
    pub cf_domain_prefix: Option<String>,
    pub cf_api_token: Option<String>,
    pub cf_seed_dump: Option<String>,
    pub cf_max_seeds: Option<usize>,
}

fn get_str_from_table<'a>(table: &'a toml::Table, key: &str) -> Option<&'a str> {
    table.get(key).and_then(|v| match v {
        toml::Value::String(s) => Some(s.as_str()),
        toml::Value::Integer(n) => Some(Box::leak(Box::new(n.to_string()))),
        _ => None,
    })
}

fn parse_toml_int<T: std::str::FromStr>(table: &toml::Table, key: &str) -> Result<T, String> {
    let raw = get_str_from_table(table, key)
        .ok_or_else(|| format!("missing or invalid config key: {key}"))?;
    raw.trim_matches('"')
        .parse::<T>()
        .map_err(|_| format!("failed to parse {key}: {raw}"))
}

impl Config {
    pub fn from_str(input: &str) -> Result<Self, String> {
        let table = toml::from_str(input).map_err(|e| format!("parse error: {e}"))?;
        Self::from_table(&table)
    }

    fn from_table(table: &toml::Table) -> Result<Self, String> {
        Ok(Config {
            protocol_version: parse_toml_int(table, "protocol_version")?,
            init_proto_version: parse_toml_int(table, "init_proto_version")?,
            min_peer_proto_version: parse_toml_int(table, "min_peer_proto_version")?,
            caddr_time_version: {
                let raw = get_str_from_table(table, "caddr_time_version").unwrap_or("0");
                let trimmed = raw.trim_matches('"');
                if trimmed.is_empty() { 0 } else { trimmed.parse::<u32>().unwrap_or(0) }
            },
            pch_message_start: {
                let mut start = [0u8; 4];
                for i in 0..4 {
                    let key = format!("pchMessageStart_{i}");
                    let raw = get_str_from_table(table, &key)
                        .ok_or_else(|| format!("missing config key: {key}"))?;
                    let trimmed = raw.trim_matches('"');
                    start[i] = if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
                        u8::from_str_radix(hex, 16).map_err(|_| format!("invalid hex: {trimmed}"))?
                    } else {
                        trimmed.parse::<u8>().map_err(|_| format!("invalid byte: {trimmed}"))?
                    };
                }
                start
            },
            wallet_port: parse_toml_int(table, "wallet_port")?,
            explorer_url: get_str_from_table(table, "explorer_url")
                .filter(|s| !s.trim_matches('"').is_empty())
                .map(|s| s.trim_matches('"').to_string()),
            second_explorer_url: get_str_from_table(table, "second_explorer_url")
                .filter(|s| !s.trim_matches('"').is_empty())
                .map(|s| s.trim_matches('"').to_string()),
            explorer_requery_seconds: {
                let raw = get_str_from_table(table, "explorer_requery_seconds").unwrap_or("60");
                raw.trim_matches('"').parse::<u64>().unwrap_or(60)
            },
            block_count: parse_toml_int(table, "block_count")?,
            seeds: {
                let mut seeds = Vec::new();
                for i in 1..=10 {
                    let key = format!("seed_{i}");
                    if let Some(v) = get_str_from_table(table, &key) {
                        let trimmed = v.trim_matches('"');
                        if !trimmed.is_empty() {
                            seeds.push(trimmed.to_string());
                        }
                    }
                }
                seeds
            },
            cf_domain: get_str_from_table(table, "cf_domain")
                .filter(|s| !s.trim_matches('"').is_empty())
                .map(|s| s.trim_matches('"').to_string()),
            cf_domain_prefix: get_str_from_table(table, "cf_domain_prefix")
                .filter(|s| !s.trim_matches('"').is_empty())
                .map(|s| s.trim_matches('"').to_string()),
            cf_api_token: get_str_from_table(table, "cf_api_key")
                .or_else(|| get_str_from_table(table, "cf_api_token"))
                .filter(|s| !s.trim_matches('"').is_empty())
                .map(|s| s.trim_matches('"').to_string()),
            cf_seed_dump: get_str_from_table(table, "cf_seed_dump")
                .filter(|s| !s.trim_matches('"').is_empty())
                .map(|s| s.trim_matches('"').to_string()),
            cf_max_seeds: Some(25),
        })
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("cannot read config: {e}"))?;
        let table = toml::from_str(&content).map_err(|e| format!("parse error: {e}"))?;
        Self::from_table(&table)
    }
}

pub mod toml {
    use std::collections::BTreeMap;

    #[derive(Debug, Clone)]
    pub enum Value {
        String(String),
        Integer(i64),
        Float(f64),
        Boolean(bool),
        Table(BTreeMap<String, Value>),
    }

    impl Value {
        pub fn as_str(&self) -> Option<&str> {
            match self {
                Value::String(s) => Some(s.as_str()),
                _ => None,
            }
        }

        pub fn as_integer(&self) -> Option<i64> {
            match self {
                Value::Integer(i) => Some(*i),
                _ => None,
            }
        }
    }

    pub type Table = BTreeMap<String, Value>;

    pub fn from_str(input: &str) -> Result<Table, String> {
        let mut table = BTreeMap::new();
        for line in input.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }
            if let Some(eq_pos) = trimmed.find('=') {
                let key = trimmed[..eq_pos].trim().to_string();
                let value_part = trimmed[eq_pos + 1..].trim();
                let value = if value_part.starts_with('"') {
                    let end = value_part
                        .rfind('"')
                        .ok_or_else(|| format!("unclosed quote in: {trimmed}"))?;
                    let inner = &value_part[1..end];
                    let inner = inner.split("//").next().unwrap_or(inner);
                    let inner = inner.split('#').next().unwrap_or(inner);
                    Value::String(inner.trim().to_string())
                } else if value_part.starts_with("0x") || value_part.starts_with("0X") {
                    Value::String(value_part.to_string())
                } else if let Ok(n) = value_part.parse::<i64>() {
                    Value::Integer(n)
                } else if let Ok(f) = value_part.parse::<f64>() {
                    Value::Float(f)
                } else if value_part == "true" {
                    Value::Boolean(true)
                } else if value_part == "false" {
                    Value::Boolean(false)
                } else {
                    let clean = value_part
                        .split("//").next().unwrap_or(&value_part)
                        .split('#').next().unwrap_or(&value_part)
                        .trim();
                    Value::String(clean.to_string())
                };
                table.insert(key, value);
            }
        }
        Ok(table)
    }
}

#[cfg(test)]
mod tests {
    use super::toml;
    use super::Config;

    #[test]
    fn test_toml_parse_key_value() {
        let table = toml::from_str("key = \"value\"\n").unwrap();
        assert_eq!(table["key"].as_str(), Some("value"));
    }

    #[test]
    fn test_toml_parse_integer() {
        let table = toml::from_str("port = 60777\n").unwrap();
        assert_eq!(table["port"].as_integer(), Some(60777));
    }

    #[test]
    fn test_toml_parse_hex() {
        let table = toml::from_str("flag = 0x63\n").unwrap();
        assert_eq!(table["flag"].as_str(), Some("0x63"));
    }

    #[test]
    fn test_toml_parse_comment() {
        let table = toml::from_str("key = \"val\" # inline comment\n").unwrap();
        assert_eq!(table["key"].as_str(), Some("val"));
    }

    #[test]
    fn test_toml_parse_empty() {
        let table = toml::from_str("").unwrap();
        assert!(table.is_empty());
    }

    #[test]
    fn test_toml_parse_comment_only() {
        let table = toml::from_str("# comment\n// also comment\n").unwrap();
        assert!(table.is_empty());
    }

    #[test]
    fn test_toml_parse_boolean() {
        let table = toml::from_str("enabled = true\ndisabled = false\n").unwrap();
        match &table["enabled"] {
            toml::Value::Boolean(b) => assert!(*b),
            _ => panic!("expected boolean"),
        }
        match &table["disabled"] {
            toml::Value::Boolean(b) => assert!(!*b),
            _ => panic!("expected boolean"),
        }
    }

    #[test]
    fn test_config_from_str_minimal() {
        let raw = r#"
protocol_version = "70028"
init_proto_version = "209"
min_peer_proto_version = "70025"
pchMessageStart_0 = "0x63"
pchMessageStart_1 = "0x56"
pchMessageStart_2 = "0x65"
pchMessageStart_3 = "0x65"
wallet_port = "60777"
block_count = "0"
"#;
        let cfg = Config::from_str(raw).unwrap();
        assert_eq!(cfg.protocol_version, 70028);
        assert_eq!(cfg.init_proto_version, 209);
        assert_eq!(cfg.min_peer_proto_version, 70025);
        assert_eq!(cfg.pch_message_start, [0x63, 0x56, 0x65, 0x65]);
        assert_eq!(cfg.wallet_port, 60777);
        assert_eq!(cfg.block_count, 0);
    }

    #[test]
    fn test_config_with_seeds() {
        let raw = r#"
protocol_version = "70028"
init_proto_version = "209"
min_peer_proto_version = "70025"
pchMessageStart_0 = "0x63"
pchMessageStart_1 = "0x56"
pchMessageStart_2 = "0x65"
pchMessageStart_3 = "0x65"
wallet_port = "60777"
block_count = "0"
seed_1 = "xnode1.satoverse.io"
seed_2 = "xnode2.satoverse.io"
"#;
        let cfg = Config::from_str(raw).unwrap();
        assert_eq!(cfg.seeds.len(), 2);
        assert_eq!(cfg.seeds[0], "xnode1.satoverse.io");
        assert_eq!(cfg.seeds[1], "xnode2.satoverse.io");
    }

    #[test]
    fn test_config_missing_required() {
        let raw = "wallet_port = \"60777\"\n";
        assert!(Config::from_str(raw).is_err());
    }
}
