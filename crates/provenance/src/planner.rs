//! The planner boundary: the planner context accepts only trusted values, untrusted values pass as opaque variable references, and a proposed input takes the label of its variable or, as a literal, the join of the context (T-36 (2), SEC-12).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::label::{Label, TrustedLabel};
use crate::value::{Labelled, Trusted};

/// An opaque reference to a bound value, written `var_<n>` with `n` up to six digits; it carries no part of the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarRef(u32);

impl VarRef {
    const MAX: u32 = 999_999;

    /// Parses the canonical `var_<n>` form.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let digits = text.strip_prefix("var_")?;
        let canonical = !digits.is_empty()
            && digits.len() <= 6
            && digits.bytes().all(|b| b.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'));
        if !canonical {
            return None;
        }
        digits.parse().ok().filter(|n| *n <= Self::MAX).map(Self)
    }
}

impl fmt::Display for VarRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "var_{}", self.0)
    }
}

impl Serialize for VarRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for VarRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| D::Error::custom("expected var_<n>"))
    }
}

/// The values bound for one task; the planner sees only their references.
pub struct VariableTable<T> {
    values: BTreeMap<VarRef, Labelled<T>>,
    next: u32,
}

impl<T> Default for VariableTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> VariableTable<T> {
    /// An empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            values: BTreeMap::new(),
            next: 1,
        }
    }

    /// Binds a value to the next free reference; `None` when every reference is taken.
    pub fn bind(&mut self, value: impl Into<Labelled<T>>) -> Option<VarRef> {
        let var = loop {
            if self.next > VarRef::MAX {
                return None;
            }
            let var = VarRef(self.next);
            self.next = self.next.saturating_add(1);
            if !self.values.contains_key(&var) {
                break var;
            }
        };
        self.values.insert(var, value.into());
        Some(var)
    }

    /// Binds a value to a given reference, returning the value it replaces.
    pub fn insert(&mut self, var: VarRef, value: impl Into<Labelled<T>>) -> Option<Labelled<T>> {
        self.values.insert(var, value.into())
    }

    /// The bound value, for the code that fills an approved intent.
    #[must_use]
    pub fn get(&self, var: VarRef) -> Option<&Labelled<T>> {
        self.values.get(&var)
    }

    /// The label of a reference; an unknown reference is `external.unknown` (SEC-12, SEC-14 (2)).
    #[must_use]
    pub fn label(&self, var: VarRef) -> Label {
        self.values
            .get(&var)
            .map_or(Label::UNKNOWN, Labelled::label)
    }
}

impl<T> fmt::Debug for VariableTable<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.values.iter()).finish()
    }
}

/// What the planner may read: trusted values as content and untrusted values only as references with their labels (T-36 (2)).
pub struct PlannerContext<T> {
    trusted: Vec<Trusted<T>>,
    variables: Vec<(VarRef, Label)>,
}

impl<T> Default for PlannerContext<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> PlannerContext<T> {
    /// An empty context.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            trusted: Vec::new(),
            variables: Vec::new(),
        }
    }

    /// Adds a trusted value as content; an untrusted value does not compile here (T-36 (2)).
    ///
    /// ```compile_fail
    /// use one_provenance::{ExternalSource, PlannerContext, Untrusted};
    /// let mut context = PlannerContext::new();
    /// context.push_trusted(Untrusted::external("x", ExternalSource::Web));
    /// ```
    pub fn push_trusted(&mut self, value: Trusted<T>) {
        self.trusted.push(value);
    }

    /// Adds a bound value by reference only.
    pub fn push_variable<V>(&mut self, table: &VariableTable<V>, var: VarRef) {
        self.variables.push((var, table.label(var)));
    }

    /// The trusted values.
    #[must_use]
    pub fn trusted(&self) -> &[Trusted<T>] {
        &self.trusted
    }

    /// The references with their labels.
    #[must_use]
    pub fn variables(&self) -> &[(VarRef, Label)] {
        &self.variables
    }

    /// The join of the trusted content, the label of every literal the planner writes; `None` for a context without content.
    #[must_use]
    pub fn literal_label(&self) -> Option<TrustedLabel> {
        self.trusted
            .iter()
            .map(Trusted::label)
            .reduce(TrustedLabel::join)
    }
}

impl<T> fmt::Debug for PlannerContext<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlannerContext")
            .field("trusted", &self.trusted)
            .field("variables", &self.variables)
            .finish()
    }
}

/// One input of a planner proposal: a literal the planner wrote or a reference to a bound value (`intent-model-output/v1`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProposedInput<T> {
    /// A literal value.
    Literal(T),
    /// A reference to a bound value.
    Ref(VarRef),
}

impl<T> ProposedInput<T> {
    /// The input's label: the variable's label for a reference, the context join for a literal (T-36 (2)).
    #[must_use]
    pub fn label<V>(&self, variables: &VariableTable<V>, context: TrustedLabel) -> Label {
        match self {
            Self::Literal(_) => Label::Trusted(context),
            Self::Ref(var) => variables.label(*var),
        }
    }
}

impl<T> fmt::Debug for ProposedInput<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(_) => f.write_str("Literal([masked])"),
            Self::Ref(var) => f.debug_tuple("Ref").field(var).finish(),
        }
    }
}
