//! The bounds every parser takes and the error it returns; errors never carry input content (T-37 (1)).

use core::fmt;
use core::mem::size_of;

/// The bounds of one parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest input accepted, in bytes.
    pub max_bytes: usize,
    /// The deepest nesting accepted; never above [`Limits::HARD_MAX_DEPTH`].
    pub max_depth: usize,
    /// The most items accepted: values, keys, headers, parts, properties or tags.
    pub max_items: usize,
    /// The longest single string accepted, in bytes.
    pub max_string: usize,
    /// The most bytes the decoded output may allocate.
    pub max_total: usize,
}

impl Limits {
    /// The ceiling on nesting depth, whatever `max_depth` says.
    pub const HARD_MAX_DEPTH: usize = 128;

    /// The default bounds.
    pub const DEFAULT: Self = Self {
        max_bytes: 1_048_576,
        max_depth: 32,
        max_items: 16_384,
        max_string: 262_144,
        max_total: 8_388_608,
    };

    const fn depth(&self) -> usize {
        if self.max_depth < Self::HARD_MAX_DEPTH {
            self.max_depth
        } else {
            Self::HARD_MAX_DEPTH
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why a parse was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The input is longer than `max_bytes`.
    TooLarge,
    /// The nesting is deeper than `max_depth`.
    TooDeep,
    /// The input has more items than `max_items`.
    TooManyItems,
    /// A string is longer than `max_string`.
    StringTooLong,
    /// The decoded output would allocate more than `max_total`.
    BudgetExceeded,
    /// An indefinite-length item where deterministic CBOR is required.
    Indefinite,
    /// A well-formed encoding that is not the deterministic one.
    NonCanonical(&'static str),
    /// The input is not well formed.
    Malformed(&'static str),
    /// The input breaks a contract rule.
    Contract(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("input too large"),
            Self::TooDeep => f.write_str("nesting too deep"),
            Self::TooManyItems => f.write_str("too many items"),
            Self::StringTooLong => f.write_str("string too long"),
            Self::BudgetExceeded => f.write_str("allocation budget exceeded"),
            Self::Indefinite => f.write_str("indefinite-length item"),
            Self::NonCanonical(what) => write!(f, "non-canonical encoding: {what}"),
            Self::Malformed(what) => write!(f, "malformed input: {what}"),
            Self::Contract(what) => write!(f, "contract violation: {what}"),
        }
    }
}

impl core::error::Error for ParseError {}

impl From<one_proto::ontology::validate::ContractViolation> for ParseError {
    fn from(v: one_proto::ontology::validate::ContractViolation) -> Self {
        Self::Contract(v.0)
    }
}

/// The running account of one parse against its [`Limits`].
#[derive(Debug)]
pub(crate) struct Budget {
    items_left: usize,
    total_left: usize,
    max_string: usize,
    max_depth: usize,
}

impl Budget {
    pub(crate) const fn new(limits: &Limits, input_len: usize) -> Result<Self, ParseError> {
        if input_len > limits.max_bytes {
            return Err(ParseError::TooLarge);
        }
        Ok(Self {
            items_left: limits.max_items,
            total_left: limits.max_total,
            max_string: limits.max_string,
            max_depth: limits.depth(),
        })
    }

    pub(crate) const fn depth(&self, depth: usize) -> Result<(), ParseError> {
        if depth > self.max_depth {
            Err(ParseError::TooDeep)
        } else {
            Ok(())
        }
    }

    pub(crate) const fn items_left(&self) -> usize {
        self.items_left
    }

    pub(crate) fn items(&mut self, n: usize) -> Result<(), ParseError> {
        self.items_left = self
            .items_left
            .checked_sub(n)
            .ok_or(ParseError::TooManyItems)?;
        Ok(())
    }

    pub(crate) fn item<T>(&mut self) -> Result<(), ParseError> {
        self.items(1)?;
        self.alloc(size_of::<T>())
    }

    pub(crate) fn alloc(&mut self, bytes: usize) -> Result<(), ParseError> {
        self.total_left = self
            .total_left
            .checked_sub(bytes)
            .ok_or(ParseError::BudgetExceeded)?;
        Ok(())
    }

    pub(crate) fn alloc_many<T>(&mut self, n: usize) -> Result<(), ParseError> {
        let bytes = n
            .checked_mul(size_of::<T>())
            .ok_or(ParseError::BudgetExceeded)?;
        self.alloc(bytes)
    }

    pub(crate) const fn string_len(&self, len: usize) -> Result<(), ParseError> {
        if len > self.max_string {
            Err(ParseError::StringTooLong)
        } else {
            Ok(())
        }
    }

    pub(crate) fn string(&mut self, len: usize) -> Result<(), ParseError> {
        self.string_len(len)?;
        self.alloc(len)
    }
}
