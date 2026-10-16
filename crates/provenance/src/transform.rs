//! Label-carrying transforms: summarising, translating, quarantine extraction, normalisation and memory writes never clear a label; only `user.direct` written to memory becomes `user.memory` (SEC-14 (1), SEC-13 (3), SEC-21 (2), T-36 (3)).

use crate::label::{Label, TrustedLabel};

/// A transform that derives one value from one or more labelled inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transform {
    /// Any combination of values into one.
    Combine,
    /// A summary.
    Summarise,
    /// A translation.
    Translate,
    /// Typed extraction by the quarantine model.
    QuarantineExtract,
    /// Removal of hidden markup and invisible characters.
    NormaliseText,
    /// A memory write.
    MemoryWrite,
}

impl Transform {
    /// The label of the derived value: the join of the inputs, with `user.direct` becoming `user.memory` on a memory write; `None` without inputs.
    #[must_use]
    pub fn label<'a>(self, inputs: impl IntoIterator<Item = &'a Label>) -> Option<Label> {
        let joined = Label::join_all(inputs)?;
        Some(match (self, joined) {
            (Self::MemoryWrite, Label::Trusted(TrustedLabel::UserDirect)) => {
                Label::Trusted(TrustedLabel::UserMemory)
            }
            (_, label) => label,
        })
    }
}
