//! The typed purchase intent of `app.suiss.commerce.purchase`: the offer it came from, items, a total limit and payment only through Pay; no card or bank field exists (A-31, A-34, A-49).

use alloc::vec::Vec;
use core::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use crate::money::Money;
use crate::ontology::Instant;
use crate::ontology::MandateRef;
use crate::ontology::OpaqueId;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::require;
use crate::task::Origin;
use crate::task::common::{Line, checked_record, wire_enum};

/// The merchant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Merchant {
    /// The merchant.
    pub merchant_ref: OpaqueId,
    /// Its origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
}

fn check_item(item: &PurchaseItem) -> Result<(), ContractViolation> {
    require(item.title.as_str().chars().count() <= 256, "item title")
}

checked_record!(
    /// One item.
    #[derive(Eq)]
    pub struct PurchaseItem via PurchaseItemWire = "PurchaseItemWire", check check_item {
        /// The product.
        pub product_ref: OpaqueId,
        /// Its title.
        pub title: Line,
        /// How many.
        pub quantity: NonZeroU32,
        /// The unit price.
        pub unit_price: Money,
    }
);

/// Where it is delivered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    /// The address.
    pub address_ref: OpaqueId,
    /// The window start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_start: Option<Instant>,
    /// The window end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_end: Option<Instant>,
}

wire_enum!(
    /// How a purchase is paid.
    PaymentVia {
        /// Always Pay.
        Pay = "pay",
    }
);

/// Payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payment {
    /// Always Pay.
    pub via: PaymentVia,
    /// The Mandate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandate_ref: Option<MandateRef>,
}

fn check_purchase(value: &PurchaseInput) -> Result<(), ContractViolation> {
    require(!value.items.is_empty(), "at least one item")
}

checked_record!(
    /// The typed purchase intent of a task (A-49).
    pub struct PurchaseInput via PurchaseInputWire = "PurchaseInputWire", check check_purchase {
        /// The merchant.
        pub merchant: Merchant,
        /// The offer it came from.
        pub offer_ref: OpaqueId,
        /// The items.
        pub items: Vec<PurchaseItem>,
        /// The total limit.
        pub total_limit: Money,
        /// Delivery.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delivery: Option<Delivery>,
        /// Payment.
        pub payment: Payment,
        /// The return terms.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub return_terms_ref: Option<OpaqueId>,
    }
);
