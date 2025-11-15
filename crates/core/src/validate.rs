use crate::errors::ValidationError;
use chrono::{DateTime, Duration, Utc};
use regex::Regex;

const ALLOWED_TYPES: &[&str] = &[
    "fact",
    "preference",
    "profile",
    "reminder",
    "note",
    "policy",
];

pub fn is_valid_type(t: &str) -> bool {
    ALLOWED_TYPES.contains(&t)
}

pub fn normalize_type(t: Option<&str>) -> Result<String, ValidationError> {
    match t {
        Some(v) if is_valid_type(v) => Ok(v.to_owned()),
        Some(v) => Err(ValidationError::InvalidType(v.to_owned())),
        None => Ok("note".to_owned()),
    }
}

/// Parse a subset of ISO-8601 durations like PnD, PTnH, PTnM, PTnS or combinations: PnDTnHnMnS.
/// Returns None if parsing fails or duration would be zero/negative.
pub fn parse_ttl_iso8601(s: &str) -> Option<Duration> {
    // Example matches: P1D, PT2H, PT30M, PT45S, P1DT2H30M15S
    let re =
        Regex::new(r"^P(?:(?P<d>\d+)D)?(?:T(?:(?P<h>\d+)H)?(?:(?P<m>\d+)M)?(?:(?P<s>\d+)S)?)?$")
            .ok()?;
    let caps = re.captures(s)?;
    let days = caps
        .name("d")
        .and_then(|m| m.as_str().parse::<i64>().ok())
        .unwrap_or(0);
    let hours = caps
        .name("h")
        .and_then(|m| m.as_str().parse::<i64>().ok())
        .unwrap_or(0);
    let mins = caps
        .name("m")
        .and_then(|m| m.as_str().parse::<i64>().ok())
        .unwrap_or(0);
    let secs = caps
        .name("s")
        .and_then(|m| m.as_str().parse::<i64>().ok())
        .unwrap_or(0);
    let total = Duration::days(days)
        + Duration::hours(hours)
        + Duration::minutes(mins)
        + Duration::seconds(secs);
    if total <= Duration::seconds(0) {
        None
    } else {
        Some(total)
    }
}

/// Returns true if the memory with given created_at and ttl string is not expired at now.
pub fn ttl_not_expired(created_at: DateTime<Utc>, ttl: &str, now: DateTime<Utc>) -> bool {
    match parse_ttl_iso8601(ttl) {
        Some(dur) => created_at + dur > now,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ttl_valid_forms() {
        assert!(parse_ttl_iso8601("P1D").is_some());
        assert!(parse_ttl_iso8601("PT2H").is_some());
        assert!(parse_ttl_iso8601("PT30M").is_some());
        assert!(parse_ttl_iso8601("PT45S").is_some());
        assert!(parse_ttl_iso8601("P1DT2H30M15S").is_some());
        assert!(parse_ttl_iso8601("P0D").is_none());
        assert!(parse_ttl_iso8601("T2H").is_none());
    }

    #[test]
    fn ttl_expiry_logic() {
        let now = Utc::now();
        let created = now - Duration::hours(2);
        assert!(ttl_not_expired(created, "PT3H", now));
        assert!(!ttl_not_expired(created, "PT1H", now));
    }
}
