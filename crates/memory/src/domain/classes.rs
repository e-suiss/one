//! The trust class shown instead of a number (M-14, `conformance/memory/trust-class-v1.toml`): what the user said or confirmed is "you said", unconfirmed external content and imports keep their "not verified" labels, and the rest is "I think" from a trust of 0.7 and "not sure" below.

use one_proto::memory::fields::SourceKind;
use one_proto::memory::text_view::TrustClass;

/// The lowest trust shown as "I think".
pub const I_THINK_MIN: f64 = 0.7;

/// The class of a record from `source`, confirmed by the user or not, with `trust`.
#[must_use]
pub fn trust_class(source: SourceKind, user_confirmed: bool, trust: f64) -> TrustClass {
    if user_confirmed || source == SourceKind::UserStatement {
        return TrustClass::YouSaid;
    }
    match source {
        SourceKind::ExternalContent => TrustClass::SeenUnverified,
        SourceKind::Import => TrustClass::ImportedUnverified,
        _ if trust >= I_THINK_MIN => TrustClass::IThink,
        _ => TrustClass::NotSure,
    }
}
