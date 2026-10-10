//! The closed list of telemetry field names, kept equal to `conformance/data-inventory.toml` by `cargo xtask check data-inventory` (T-37 (1, 3), T-40 (4, 5), §18 OP-17 (4)).

use crate::Value;

/// The kind of value a field carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// [`Value::Id`].
    Id,
    /// [`Value::Count`].
    Count,
    /// [`Value::Millis`].
    Millis,
    /// [`Value::Number`].
    Number,
}

/// A telemetry field name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// Request identifier.
    RequestId,
    /// Opaque task identifier.
    TaskId,
    /// HTTP status code.
    HttpStatus,
    /// Duration of the operation in milliseconds.
    DurationMs,
    /// Number of items processed.
    Items,
    /// Attempt number of an outbound call.
    Attempt,
}

/// One row of the closed list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spec {
    /// The field.
    pub field: Field,
    /// Stable wire name.
    pub name: &'static str,
    /// Accepted value kind.
    pub kind: Kind,
    /// Whether the field may be a metric label.
    pub label: bool,
}

/// Every field, in inventory order.
pub const ALL: &[Spec] = &[
    Spec {
        field: Field::RequestId,
        name: "request_id",
        kind: Kind::Id,
        label: false,
    },
    Spec {
        field: Field::TaskId,
        name: "task_id",
        kind: Kind::Id,
        label: false,
    },
    Spec {
        field: Field::HttpStatus,
        name: "http_status",
        kind: Kind::Number,
        label: true,
    },
    Spec {
        field: Field::DurationMs,
        name: "duration_ms",
        kind: Kind::Millis,
        label: false,
    },
    Spec {
        field: Field::Items,
        name: "items",
        kind: Kind::Count,
        label: false,
    },
    Spec {
        field: Field::Attempt,
        name: "attempt",
        kind: Kind::Count,
        label: false,
    },
];

impl Field {
    fn spec(self) -> Option<&'static Spec> {
        ALL.iter().find(|s| s.field == self)
    }

    /// The stable wire name.
    #[must_use]
    pub fn name(self) -> &'static str {
        self.spec().map_or("unknown", |s| s.name)
    }

    /// Whether `value` has this field's kind.
    #[must_use]
    pub fn accepts(self, value: &Value) -> bool {
        let kind = match value {
            Value::Id(_) => Kind::Id,
            Value::Count(_) => Kind::Count,
            Value::Millis(_) => Kind::Millis,
            Value::Number(_) => Kind::Number,
        };
        self.spec().is_some_and(|s| s.kind == kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_37_every_field_has_one_row_and_a_unique_name() {
        for spec in ALL {
            assert_eq!(ALL.iter().filter(|s| s.field == spec.field).count(), 1);
            assert_eq!(ALL.iter().filter(|s| s.name == spec.name).count(), 1);
        }
    }

    #[test]
    fn op_17_identifiers_are_never_metric_labels() {
        assert!(ALL.iter().filter(|s| s.kind == Kind::Id).all(|s| !s.label));
    }
}
