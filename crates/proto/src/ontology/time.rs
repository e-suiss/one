//! RFC 3339 UTC instants as the contracts write them (`YYYY-MM-DDTHH:MM:SS(.f{1,9})?Z`); time is always an input, never read from a clock here (C-19, T-27).

use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A UTC instant with nanosecond precision that keeps its written fraction width.
#[derive(Clone, Copy)]
pub struct Instant {
    secs: i64,
    nanos: u32,
    digits: u8,
}

/// A malformed instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstantError;

/// A non-negative span between two instants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span {
    /// Whole seconds.
    pub secs: u64,
    /// Nanoseconds below one second.
    pub nanos: u32,
}

const POW10: [u32; 10] = [
    1,
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
];

fn digits(text: &[u8]) -> Option<u32> {
    let mut value: u32 = 0;
    for &c in text {
        if !c.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u32::from(c.checked_sub(b'0')?))?;
    }
    Some(value)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let y = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = y.checked_div_euclid(400)?;
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let m = i64::from(month);
    let mp = if m > 2 {
        m.checked_sub(3)?
    } else {
        m.checked_add(9)?
    };
    let doy = mp
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(i64::from(day))?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

fn civil_from_days(days: i64) -> Option<(i64, u32, u32)> {
    let z = days.checked_add(719_468)?;
    let era = z.checked_div_euclid(146_097)?;
    let doe = z.checked_sub(era.checked_mul(146_097)?)?;
    let yoe = doe
        .checked_sub(doe.checked_div(1460)?)?
        .checked_add(doe.checked_div(36_524)?)?
        .checked_sub(doe.checked_div(146_096)?)?
        .checked_div(365)?;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe.checked_div(4)?)?
            .checked_sub(yoe.checked_div(100)?)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)?.checked_div(153)?;
    let day = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)?.checked_div(5)?)?
        .checked_add(1)?;
    let month = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let year = yoe
        .checked_add(era.checked_mul(400)?)?
        .checked_add(i64::from(month <= 2))?;
    Some((year, u32::try_from(month).ok()?, u32::try_from(day).ok()?))
}

const fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl Instant {
    /// The instant `secs` seconds after the Unix epoch, written without a fraction.
    #[must_use]
    pub const fn from_unix(secs: i64) -> Self {
        Self {
            secs,
            nanos: 0,
            digits: 0,
        }
    }

    /// Seconds since the Unix epoch.
    #[must_use]
    pub const fn unix_secs(&self) -> i64 {
        self.secs
    }

    /// Nanoseconds below the second.
    #[must_use]
    pub const fn subsec_nanos(&self) -> u32 {
        self.nanos
    }

    /// The number of fraction digits as written, 0 to 9.
    #[must_use]
    pub const fn fraction_digits(&self) -> u8 {
        self.digits
    }

    /// The span from `earlier` to `self`, or `None` when `earlier` is later.
    #[must_use]
    pub fn since(&self, earlier: &Self) -> Option<Span> {
        if self < earlier {
            return None;
        }
        let mut secs = self.secs.checked_sub(earlier.secs)?;
        let nanos = if self.nanos >= earlier.nanos {
            self.nanos.checked_sub(earlier.nanos)?
        } else {
            secs = secs.checked_sub(1)?;
            self.nanos
                .checked_add(1_000_000_000)?
                .checked_sub(earlier.nanos)?
        };
        Some(Span {
            secs: u64::try_from(secs).ok()?,
            nanos,
        })
    }

    /// Parses the contract form.
    ///
    /// # Errors
    /// Rejects any other form, an impossible date or a time past 23:59:59.
    pub fn parse(text: &str) -> Result<Self, InstantError> {
        let b = text.as_bytes();
        let field = |from: usize, to: usize| b.get(from..to).and_then(digits).ok_or(InstantError);
        let sep = |at: usize, c: u8| {
            if b.get(at) == Some(&c) {
                Ok(())
            } else {
                Err(InstantError)
            }
        };
        let year = field(0, 4)?;
        sep(4, b'-')?;
        let month = field(5, 7)?;
        sep(7, b'-')?;
        let day = field(8, 10)?;
        sep(10, b'T')?;
        let hour = field(11, 13)?;
        sep(13, b':')?;
        let minute = field(14, 16)?;
        sep(16, b':')?;
        let second = field(17, 19)?;
        let rest = b.get(19..).ok_or(InstantError)?;
        let (nanos, width) = match rest {
            [b'Z'] => (0, 0),
            [b'.', frac @ .., b'Z'] if (1..=9).contains(&frac.len()) => {
                let value = digits(frac).ok_or(InstantError)?;
                let width = u8::try_from(frac.len()).map_err(|_| InstantError)?;
                let scale = POW10
                    .get(9_usize.checked_sub(frac.len()).ok_or(InstantError)?)
                    .ok_or(InstantError)?;
                (value.checked_mul(*scale).ok_or(InstantError)?, width)
            }
            _ => return Err(InstantError),
        };
        let year = i64::from(year);
        if !(1..=12).contains(&month)
            || day == 0
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(InstantError);
        }
        let days = days_from_civil(year, month, day).ok_or(InstantError)?;
        let tod = i64::from(hour)
            .checked_mul(3600)
            .and_then(|h| h.checked_add(i64::from(minute).checked_mul(60)?))
            .and_then(|s| s.checked_add(i64::from(second)))
            .ok_or(InstantError)?;
        let secs = days
            .checked_mul(86_400)
            .and_then(|d| d.checked_add(tod))
            .ok_or(InstantError)?;
        Ok(Self {
            secs,
            nanos,
            digits: width,
        })
    }
}

/// An ISO 8601 duration with whole-number fields, `P[nY][nM][nW][nD][T[nH][nM][nS]]`, as Access Appendix C writes retention periods (PV-17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CalendarDuration {
    /// Calendar months, years counted as twelve.
    pub months: u32,
    /// Days, weeks counted as seven.
    pub days: u32,
    /// Seconds of the time part.
    pub seconds: u64,
}

impl CalendarDuration {
    /// Parses the duration.
    ///
    /// # Errors
    /// Rejects an empty duration, a fraction, a sign, a repeated or out-of-order designator and an overflow.
    pub fn parse(text: &str) -> Result<Self, InstantError> {
        let body = text.strip_prefix('P').ok_or(InstantError)?;
        let (date, time) = match body.split_once('T') {
            Some((d, t)) if !t.is_empty() => (d, Some(t)),
            Some(_) => return Err(InstantError),
            None => (body, None),
        };
        let mut out = Self::default();
        let mut any = false;
        let mut rank = 0;
        for (value, unit) in fields(date)? {
            let next = match unit {
                b'Y' => 1,
                b'M' => 2,
                b'W' => 3,
                b'D' => 4,
                _ => return Err(InstantError),
            };
            if next <= rank {
                return Err(InstantError);
            }
            rank = next;
            any = true;
            let v = u32::try_from(value).map_err(|_| InstantError)?;
            match unit {
                b'Y' => out.months = add32(out.months, v.checked_mul(12))?,
                b'M' => out.months = add32(out.months, Some(v))?,
                b'W' => out.days = add32(out.days, v.checked_mul(7))?,
                _ => out.days = add32(out.days, Some(v))?,
            }
        }
        rank = 0;
        for (value, unit) in fields(time.unwrap_or_default())? {
            let (next, scale) = match unit {
                b'H' => (1, 3600),
                b'M' => (2, 60),
                b'S' => (3, 1),
                _ => return Err(InstantError),
            };
            if next <= rank {
                return Err(InstantError);
            }
            rank = next;
            any = true;
            out.seconds = value
                .checked_mul(scale)
                .and_then(|s| out.seconds.checked_add(s))
                .ok_or(InstantError)?;
        }
        if any { Ok(out) } else { Err(InstantError) }
    }
}

fn add32(a: u32, b: Option<u32>) -> Result<u32, InstantError> {
    b.and_then(|b| a.checked_add(b)).ok_or(InstantError)
}

fn fields(text: &str) -> Result<Vec<(u64, u8)>, InstantError> {
    let mut out = Vec::new();
    let mut value: Option<u64> = None;
    for c in text.bytes() {
        if c.is_ascii_digit() {
            let digit = u64::from(c.checked_sub(b'0').ok_or(InstantError)?);
            value = Some(
                value
                    .unwrap_or(0)
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(digit))
                    .ok_or(InstantError)?,
            );
        } else {
            out.push((value.take().ok_or(InstantError)?, c));
        }
    }
    if value.is_some() {
        return Err(InstantError);
    }
    Ok(out)
}

impl Instant {
    /// The instant `d` after `self` in calendar terms: months first, keeping the day of month and clamping it to the month's last day, then days and seconds; `None` on overflow.
    #[must_use]
    pub fn checked_add_calendar(&self, d: &CalendarDuration) -> Option<Self> {
        let days = self.secs.div_euclid(86_400);
        let tod = self.secs.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days)?;
        let index = year
            .checked_mul(12)?
            .checked_add(i64::from(month))?
            .checked_sub(1)?
            .checked_add(i64::from(d.months))?;
        let year = index.div_euclid(12);
        let month = u32::try_from(index.rem_euclid(12).checked_add(1)?).ok()?;
        let day = day.min(days_in_month(year, month));
        let secs = days_from_civil(year, month, day)?
            .checked_add(i64::from(d.days))?
            .checked_mul(86_400)?
            .checked_add(tod)?
            .checked_add(i64::try_from(d.seconds).ok()?)?;
        Some(Self {
            secs,
            nanos: self.nanos,
            digits: self.digits,
        })
    }
}

impl PartialEq for Instant {
    fn eq(&self, other: &Self) -> bool {
        self.secs == other.secs && self.nanos == other.nanos
    }
}

impl Eq for Instant {}

impl PartialOrd for Instant {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Instant {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.secs, self.nanos).cmp(&(other.secs, other.nanos))
    }
}

impl core::hash::Hash for Instant {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.secs.hash(state);
        self.nanos.hash(state);
    }
}

impl fmt::Display for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.secs.div_euclid(86_400);
        let tod = self.secs.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days).ok_or(fmt::Error)?;
        let hour = tod.checked_div(3600).ok_or(fmt::Error)?;
        let minute = tod.rem_euclid(3600).checked_div(60).ok_or(fmt::Error)?;
        let second = tod.rem_euclid(60);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"
        )?;
        if self.digits > 0 {
            let width = usize::from(self.digits);
            let scale = POW10
                .get(9_usize.checked_sub(width).ok_or(fmt::Error)?)
                .ok_or(fmt::Error)?;
            let frac = self.nanos.checked_div(*scale).ok_or(fmt::Error)?;
            write!(f, ".{frac:0width$}")?;
        }
        f.write_str("Z")
    }
}

impl fmt::Debug for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Instant {
    type Err = InstantError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Instant {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

struct InstantVisitor;

impl Visitor<'_> for InstantVisitor {
    type Value = Instant;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an RFC 3339 UTC instant")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Instant::parse(v).map_err(|_| E::custom(format_args!("instant {v:?}")))
    }
}

impl<'de> Deserialize<'de> for Instant {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(InstantVisitor)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::*;

    fn at(s: &str) -> Instant {
        Instant::parse(s).unwrap_or(Instant::from_unix(0))
    }

    fn add(s: &str, d: &str) -> Option<String> {
        let d = CalendarDuration::parse(d).ok()?;
        at(s)
            .checked_add_calendar(&d)
            .map(|i| alloc::format!("{i}"))
    }

    // PV-17
    #[test]
    fn pv_17_calendar_durations_add_years_months_days_and_time() {
        assert_eq!(
            add("2026-11-02T10:00:00Z", "P3Y").as_deref(),
            Some("2029-11-02T10:00:00Z")
        );
        assert_eq!(
            add("2026-11-02T10:00:00Z", "P30D").as_deref(),
            Some("2026-12-02T10:00:00Z")
        );
        assert_eq!(
            add("2026-05-01T00:00:00Z", "P6M").as_deref(),
            Some("2026-11-01T00:00:00Z")
        );
        assert_eq!(
            add("2028-02-29T00:00:00Z", "P1Y").as_deref(),
            Some("2029-02-28T00:00:00Z")
        );
        assert_eq!(
            add("2026-01-31T00:00:00Z", "P1M").as_deref(),
            Some("2026-02-28T00:00:00Z")
        );
        assert_eq!(
            add("2026-11-02T10:20:00Z", "PT1H").as_deref(),
            Some("2026-11-02T11:20:00Z")
        );
        assert_eq!(
            add("2026-11-02T10:00:00Z", "P1W").as_deref(),
            Some("2026-11-09T10:00:00Z")
        );
        assert_eq!(
            add("2026-11-02T10:00:00Z", "PT0S").as_deref(),
            Some("2026-11-02T10:00:00Z")
        );
    }

    // PV-17
    #[test]
    fn pv_17_malformed_durations_are_rejected() {
        for bad in [
            "", "P", "PT", "3D", "P1.5D", "P-1D", "P1D1Y", "P1Y1Y", "PT1M1H", "P1", "P1X",
        ] {
            assert_eq!(CalendarDuration::parse(bad), Err(InstantError), "{bad}");
        }
    }
}
