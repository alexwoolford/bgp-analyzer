//! Fact-clock helper: TEXT `YYYY-MM-DDTHH:MM:SSZ` (always `Z`, no fraction).

use anyhow::{bail, Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};

pub const INSTANT_FMT: &str = "%Y-%m-%dT%H:%M:%SZ";
pub const DATE_FMT: &str = "%Y-%m-%d";

/// Format a UTC instant for a captured fact column.
pub fn utc_iso(dt: DateTime<Utc>) -> String {
    dt.format(INSTANT_FMT).to_string()
}

/// UTC calendar day `YYYY-MM-DD`.
pub fn utc_date(dt: DateTime<Utc>) -> String {
    dt.format(DATE_FMT).to_string()
}

/// Parse a fact instant. Rejects `+00:00` and fractional seconds.
pub fn parse_utc_iso(s: &str) -> Result<DateTime<Utc>> {
    if s.contains('.') || s.contains('+') || s.ends_with("UTC") {
        bail!("fact instant must be {INSTANT_FMT}, got {s:?}");
    }
    let naive = NaiveDateTime::parse_from_str(s, INSTANT_FMT)
        .with_context(|| format!("parsing fact instant {s:?}"))?;
    Ok(naive.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn utc_iso_is_zulu_second_resolution() {
        let dt = Utc.with_ymd_and_hms(2026, 8, 14, 0, 30, 0).unwrap();
        let s = utc_iso(dt);
        assert_eq!(s, "2026-08-14T00:30:00Z");
        assert!(!s.contains('.'));
        assert!(!s.contains('+'));
        assert_eq!(parse_utc_iso(&s).unwrap(), dt);
    }

    #[test]
    fn parse_utc_iso_rejects_offset_and_fraction() {
        assert!(parse_utc_iso("2026-08-14T00:30:00+00:00").is_err());
        assert!(parse_utc_iso("2026-08-14T00:30:00.123Z").is_err());
    }

    #[test]
    fn utc_date_is_calendar_day() {
        let dt = Utc.with_ymd_and_hms(2026, 8, 14, 0, 30, 0).unwrap();
        assert_eq!(utc_date(dt), "2026-08-14");
    }
}
