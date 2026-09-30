//! Pure DNS-record reconciliation: decide what to delete and what to add.
//!
//! Mirrors the fixed Python uploader (own-IP guarantee, working prune).

/// Result of reconciling current DNS records against crawl candidates.
pub struct ReconcilePlan {
    /// Records to delete (stale + over-cap overflow).
    pub to_delete: Vec<String>,
    /// Candidate IPs to publish (own IP first).
    pub to_add: Vec<String>,
    /// Records kept as-is.
    pub keep: Vec<String>,
}

/// Reconcile current DNS seeds against crawl candidates.
///
/// - `current`: IPs currently published in DNS.
/// - `candidates`: good IPs from the crawl dump.
/// - `own_ip`: this seeder's own IP, always published (the crawl may not
///   contain it, and losing it from DNS is exactly the outage this
///   publisher exists to prevent).
/// - `max_seeds`: cap on published records.
pub fn reconcile(
    current: &[String],
    candidates: &[String],
    own_ip: Option<&str>,
    max_seeds: usize,
) -> ReconcilePlan {
    let mut candidates = candidates.to_vec();
    if let Some(ip) = own_ip {
        if !ip.is_empty() && !candidates.iter().any(|c| c == ip) {
            candidates.insert(0, ip.to_string());
        }
    }

    // Remove stale records (not in the candidate list).
    let mut to_delete: Vec<String> = current
        .iter()
        .filter(|s| !candidates.contains(s))
        .cloned()
        .collect();
    let mut keep: Vec<String> = current
        .iter()
        .filter(|s| !to_delete.contains(s))
        .cloned()
        .collect();

    // Prune anything above the cap (stale removal already ran, so this
    // truncates the tail — the old `>= max` + "not in candidates" filter
    // could never fire here).
    if keep.len() > max_seeds {
        let overflow: Vec<String> = keep[max_seeds..].to_vec();
        to_delete.extend(overflow.iter().cloned());
        keep.truncate(max_seeds);
    }

    // Grow towards the cap from candidates.
    let mut to_add = Vec::new();
    for seed in &candidates {
        if to_add.len() + keep.len() >= max_seeds {
            break;
        }
        if !keep.contains(seed) {
            to_add.push(seed.clone());
        }
    }

    ReconcilePlan {
        to_delete,
        to_add,
        keep,
    }
}
#[cfg(test)]
mod tests {
    use super::reconcile;

    #[test]
    fn own_ip_is_published_when_missing_from_candidates() {
        let plan = reconcile(
            &["1.1.1.1".to_string()],
            &["2.2.2.2".to_string()],
            Some("9.9.9.9"),
            25,
        );
        assert!(!plan.to_add.is_empty());
        assert_eq!(plan.to_add[0], "9.9.9.9");
    }

    #[test]
    fn stale_seeds_are_deleted() {
        let plan = reconcile(
            &["1.1.1.1".to_string(), "9.9.9.9".to_string()],
            &["1.1.1.1".to_string()],
            None,
            25,
        );
        assert_eq!(plan.to_delete, vec!["9.9.9.9".to_string()]);
    }

    #[test]
    fn over_cap_truncates_even_when_all_are_candidates() {
        // The old prune condition could never fire after stale removal;
        // truncation must still work.
        let current: Vec<String> = (0..30).map(|i| format!("10.0.0.{i}")).collect();
        let plan = reconcile(&current, &current, None, 25);
        assert_eq!(plan.keep.len(), 25);
        assert_eq!(plan.to_delete.len(), 5);
        assert!(plan.to_add.is_empty());
    }

    #[test]
    fn fills_shortfall_from_candidates() {
        let plan = reconcile(
            &["1.1.1.1".to_string()],
            &["1.1.1.1".to_string(), "2.2.2.2".to_string()],
            None,
            25,
        );
        assert_eq!(plan.to_add, vec!["2.2.2.2".to_string()]);
        assert!(plan.to_delete.is_empty());
    }
}
