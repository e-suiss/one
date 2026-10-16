//! The RELAY-NO-CONTENT check over exported Relay records, events and push payloads: only the allowed metadata members appear and no canary is found anywhere (OO-6, OO-7).

/// Members a stored mailbox record or Relay event may carry (`relay-no-content.toml`).
pub const MAILBOX_ALLOWED_FIELDS: &[&str] = &[
    "senderAccessId",
    "recipient",
    "size",
    "enqueuedAt",
    "rateBucket",
    "deliveryClass",
    "seq",
    "trustLabel",
    "ciphertext",
];

/// Members a push payload may carry: only the wake hint.
pub const PUSH_ALLOWED_FIELDS: &[&str] = &["wake"];

/// Delivery classes, assigned from the MLS wire format.
pub const DELIVERY_CLASSES: &[&str] = &[
    "mls-application",
    "mls-commit",
    "mls-welcome",
    "mls-key-package",
];

/// The first member outside `allowed`, or `None` when the export is clean.
pub fn first_disallowed<'a, I>(members: I, allowed: &[&str]) -> Option<&'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    members.into_iter().find(|m| !allowed.contains(m))
}

/// The first exported location whose text contains the canary, or `None` when none does.
pub fn canary_found<'a, I>(canary: &str, exports: I) -> Option<&'a str>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    exports
        .into_iter()
        .find(|(_, text)| text.contains(canary))
        .map(|(location, _)| location)
}
