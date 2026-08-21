
#[derive(Debug, Clone)]
pub struct BlockState {
    pub current_block: i32,
    pub from_explorer: bool,
}

pub async fn read_block_height(url: &str) -> Result<i32, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("reqwest: {e}"))?;

    let resp = client.get(url).send().await.map_err(|e| format!("http: {e}"))?;
    let text = resp.text().await.map_err(|e| format!("body: {e}"))?;
    let trimmed = text.trim();
    trimmed
        .parse::<i32>()
        .map_err(|e| format!("not a number: '{trimmed}': {e}"))
}

pub fn is_numeric(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_numeric_positive() {
        assert!(is_numeric("12345"));
        assert!(is_numeric("0"));
        assert!(is_numeric("999999999"));
    }

    #[test]
    fn test_is_numeric_negative() {
        assert!(!is_numeric(""));
        assert!(!is_numeric("12.5"));
        assert!(!is_numeric("abc"));
        assert!(!is_numeric("123abc"));
        assert!(!is_numeric("-1"));
    }

    #[test]
    fn test_block_state_default() {
        let s = BlockState { current_block: 0, from_explorer: false };
        assert_eq!(s.current_block, 0);
        assert!(!s.from_explorer);
    }
}
