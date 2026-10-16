//! Money as a decimal amount and an ISO 4217 currency code, compared only within one currency (X-3, A-1).

use core::cmp::Ordering;

use serde::{Deserialize, Serialize};

fn is_decimal(text: &str) -> bool {
    let body = text.strip_prefix('-').unwrap_or(text);
    let (int, frac) = match body.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (body, None),
    };
    let int_ok = int == "0"
        || (!int.is_empty()
            && int.len() <= 18
            && !int.starts_with('0')
            && int.bytes().all(|b| b.is_ascii_digit()));
    let frac_ok =
        frac.is_none_or(|f| (1..=8).contains(&f.len()) && f.bytes().all(|b| b.is_ascii_digit()));
    int_ok && frac_ok
}

fn is_currency(text: &str) -> bool {
    text.len() == 3 && text.bytes().all(|b| b.is_ascii_uppercase())
}

crate::ontology::validate::checked_string!(
    /// A decimal amount as text: optional minus, no leading zeros, at most 8 fraction digits.
    Decimal,
    "decimal amount",
    is_decimal
);
crate::ontology::validate::checked_string!(
    /// An ISO 4217 currency code.
    Currency,
    "currency code",
    is_currency
);

impl Decimal {
    fn parts(&self) -> (bool, &str, &str) {
        let body = self.0.strip_prefix('-').unwrap_or(&self.0);
        let (int, frac) = body.split_once('.').unwrap_or((body, ""));
        let frac = frac.trim_end_matches('0');
        let zero = int == "0" && frac.is_empty();
        (self.0.starts_with('-') && !zero, int, frac)
    }

    /// Compares two amounts numerically.
    #[must_use]
    pub fn compare(&self, other: &Self) -> Ordering {
        let (neg_a, int_a, frac_a) = self.parts();
        let (neg_b, int_b, frac_b) = other.parts();
        let magnitude = int_a
            .len()
            .cmp(&int_b.len())
            .then_with(|| int_a.cmp(int_b))
            .then_with(|| frac_a.cmp(frac_b));
        match (neg_a, neg_b) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => magnitude,
            (true, true) => magnitude.reverse(),
        }
    }
}

/// An amount in one currency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Money {
    /// The amount.
    pub value: Decimal,
    /// The currency.
    pub currency: Currency,
}

impl Money {
    /// Compares two amounts; `None` when the currencies differ.
    #[must_use]
    pub fn compare(&self, other: &Self) -> Option<Ordering> {
        (self.currency == other.currency).then(|| self.value.compare(&other.value))
    }
}
