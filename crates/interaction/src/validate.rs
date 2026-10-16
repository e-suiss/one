//! Cross-field rules of the Interaction and `InteractionResponse` schemas that types alone do not carry; an extension kind follows the rules of the core kind it maps to (X-12, X-13, X-14, X-16, X-18, X-19, X-20, X-21, X-22, X-28, X-30, C-7, C-19, C-25, C-26, AT-5, AT-6, AT-12, AT-13).

use alloc::vec::Vec;

use one_proto::data_class::{DataKind, RetentionClass};
use one_proto::ontology::validate::unique;
use one_proto::ontology::{
    AccessObjectRef, AnyRef, ProductRef, RecordStatus, Target, WorkObjectRef,
};

use crate::catalog::CATALOG_VERSION;
use crate::common::{CoreKind, Invalid, Localized, MandateFit, chars, is_line_within};
use crate::interaction::{
    ClassTighten, Delivery, Details, FieldType, Interaction, OptionItem, OutcomeStatus, Place,
};
use crate::kind::Effect;
use crate::response::{InteractionResponse, Presence, UserVerification};
use one_proto::interaction_types::Authentication;
use one_proto::interaction_types::ConsequenceTier;
use one_proto::interaction_types::Interruption;
use one_proto::interaction_types::Reversibility;
use one_proto::interaction_types::SurfaceClass;

fn check(ok: bool, what: &'static str) -> Result<(), Invalid> {
    if ok { Ok(()) } else { Err(Invalid(what)) }
}

fn is_request_or_work_item(target: &Target) -> bool {
    matches!(
        target,
        Target::Any(AnyRef::Product(
            ProductRef::Access(AccessObjectRef::DecisionRecord(_))
                | ProductRef::Work(WorkObjectRef::NeedsAttention(_))
        ))
    )
}

fn count_in<T>(items: &[T], min: usize, max: usize) -> bool {
    (min..=max).contains(&items.len())
}

fn opt_line(text: Option<&str>, max: usize) -> bool {
    text.is_none_or(|t| is_line_within(t, max))
}

fn place_ok(place: &Place) -> bool {
    is_line_within(&place.name, 120)
        && opt_line(place.address.as_deref(), 200)
        && place
            .geo
            .is_none_or(|g| (-90.0..=90.0).contains(&g.lat) && (-180.0..=180.0).contains(&g.lon))
}

fn option_ok(option: &OptionItem) -> bool {
    is_line_within(&option.title, 80)
        && opt_line(option.summary.as_deref(), 200)
        && option.place.as_ref().is_none_or(place_ok)
        && option.attributes.as_deref().is_none_or(|a| {
            a.len() <= 8
                && a.iter()
                    .all(|x| is_line_within(&x.label, 40) && is_line_within(&x.value, 80))
        })
        && option
            .image
            .as_ref()
            .is_none_or(|i| i.alt.lines_within(120))
}

fn details_ok(d: &Details) -> Result<(), Invalid> {
    check(
        d.counterparty
            .as_ref()
            .is_none_or(|c| is_line_within(&c.display, 120)),
        "details.counterparty",
    )?;
    check(d.place.as_ref().is_none_or(place_ok), "details.place")?;
    check(
        d.options
            .as_deref()
            .is_none_or(|o| count_in(o, 2, 10) && o.iter().all(option_ok)),
        "details.options",
    )?;
    check(
        d.fields.as_deref().is_none_or(|f| {
            count_in(f, 1, 20)
                && f.iter().all(|x| {
                    x.label.lines_within(60)
                        && x.max_length.is_none_or(|m| (1..=500).contains(&m))
                        && x.options.as_deref().is_none_or(|o| {
                            count_in(o, 2, 10) && o.iter().all(|c| c.label.lines_within(60))
                        })
                        && (x.field_type != FieldType::Choice || x.options.is_some())
                })
        }),
        "details.fields",
    )?;
    check(
        d.progress.as_ref().is_none_or(|p| {
            p.fraction.is_none_or(|f| (0.0..=1.0).contains(&f))
                && opt_line(p.step_label.as_deref(), 60)
        }),
        "details.progress",
    )?;
    check(
        d.steps
            .as_deref()
            .is_none_or(|s| count_in(s, 1, 100) && s.iter().all(|x| is_line_within(&x.label, 80))),
        "details.steps",
    )?;
    check(
        d.outcome.as_ref().is_none_or(|o| {
            let confirmed = !matches!(o.status, OutcomeStatus::Done | OutcomeStatus::Stopped)
                || o.executor_confirmed;
            confirmed && o.refs.as_deref().is_none_or(|r| r.len() <= 8)
        }),
        "details.outcome",
    )?;
    check(
        d.note
            .as_ref()
            .is_none_or(|n| n.untrusted && (1..=500).contains(&chars(&n.text))),
        "details.note",
    )
}

fn tighten_ok(t: &ClassTighten) -> bool {
    let any = t.visuals.is_some()
        || t.max_title_chars.is_some()
        || t.max_body_chars.is_some()
        || t.max_actions.is_some()
        || t.no_approval.is_some();
    any && t.max_title_chars.is_none_or(|v| (8..=64).contains(&v))
        && t.max_body_chars.is_none_or(|v| (16..=180).contains(&v))
        && t.max_actions.is_none_or(|v| v <= 3)
        && t.no_approval.is_none_or(|v| v)
}

fn localized(l: &Localized, max: usize, what: &'static str) -> Result<(), Invalid> {
    check(l.lines_within(max), what)
}

fn header_ok(i: &Interaction) -> Result<(), Invalid> {
    check(i.version >= 1, "version")?;
    check(
        if i.version == 1 {
            i.supersedes.is_none()
        } else {
            i.supersedes.is_some()
        },
        "supersedes",
    )?;
    check(i.domain.check().is_ok(), "domain.areas")?;
    let retention = if i.data_class.is_sensitive() {
        RetentionClass::OneSensitive
    } else {
        RetentionClass::OneMemory
    };
    check(i.retention_class == retention, "retention_class")?;
    check(
        match i.status {
            RecordStatus::Deleted => i.deleted_at.is_some(),
            RecordStatus::Active => i.deleted_at.is_none(),
        },
        "deleted_at",
    )?;
    check(i.produced_by.check().is_ok(), "produced_by")
}

fn approval_ok(i: &Interaction) -> Result<(), Invalid> {
    let fit = i.mandate_fit.ok_or(Invalid("mandate_fit"))?;
    check(is_request_or_work_item(&i.subject.reference), "subject.ref")?;
    check(
        i.has_effect(Effect::Approve) && i.has_effect(Effect::Decline),
        "actions",
    )?;
    check(i.timing.surface_policy.is_some(), "timing.surface_policy")?;
    check(
        !matches!(i.interruption, Interruption::Passive | Interruption::Active)
            || i.timing.delivery == Delivery::NextBreak,
        "timing.delivery",
    )?;
    let strong = i.risk >= ConsequenceTier::Ct2
        || i.reversibility == Reversibility::Irreversible
        || fit != MandateFit::Within;
    check(
        !strong
            || (i.min_assurance.authentication == Authentication::Passkey
                && i.min_assurance
                    .surface_classes
                    .iter()
                    .all(|c| matches!(c, SurfaceClass::Phone | SurfaceClass::Desktop))),
        "min_assurance",
    )?;
    check(
        fit != MandateFit::NonDelegable || i.min_assurance.direct_act_only == Some(true),
        "min_assurance.direct_act_only",
    )
}

fn kind_ok(i: &Interaction, kind: CoreKind) -> Result<(), Invalid> {
    let d = &i.details;
    if kind == CoreKind::Approval {
        approval_ok(i)?;
    } else {
        check(i.mandate_fit.is_none(), "mandate_fit")?;
        check(!i.has_effect(Effect::Approve), "actions.approve")?;
    }
    let picks = matches!(kind, CoreKind::Choice | CoreKind::Comparison);
    check(
        if picks {
            d.options.is_some() && i.has_effect(Effect::Choose)
        } else {
            !i.has_effect(Effect::Choose)
        },
        "actions.choose",
    )?;
    check(
        kind != CoreKind::Comparison || d.options.as_ref().is_none_or(|o| o.len() <= 4),
        "details.options",
    )?;
    check(
        (kind == CoreKind::Question) == i.has_effect(Effect::Answer),
        "actions.answer",
    )?;
    check(
        if kind == CoreKind::Form {
            d.fields.is_some() && (i.has_effect(Effect::Submit) || i.has_effect(Effect::Open))
        } else {
            d.fields.is_none() && !i.has_effect(Effect::Submit)
        },
        "details.fields",
    )?;
    check(
        kind != CoreKind::Progress
            || (d.progress.is_some()
                && i.interruption == Interruption::Passive
                && i.has_effect(Effect::Stop)),
        "progress",
    )?;
    check(
        kind != CoreKind::Receipt || d.outcome.is_some(),
        "details.outcome",
    )?;
    check(
        kind != CoreKind::DigestItem || i.interruption == Interruption::Passive,
        "interruption",
    )
}

fn actions_ok(i: &Interaction) -> Result<(), Invalid> {
    check(count_in(&i.actions, 2, 8), "actions")?;
    for a in &i.actions {
        localized(&a.label, 24, "actions.label")?;
        check(
            (a.effect == Effect::Choose) == a.option_id.is_some()
                && (a.effect == Effect::Answer) == a.value.is_some(),
            "actions.shape",
        )?;
    }
    let forbidden: &[Effect] = match i.reversibility {
        Reversibility::Irreversible => &[Effect::Undo, Effect::RequestRefund],
        Reversibility::Compensable => &[Effect::Undo],
        Reversibility::Reversible => &[Effect::RequestRefund],
    };
    check(
        !i.actions.iter().any(|a| forbidden.contains(&a.effect)),
        "actions.reversibility",
    )
}

/// Checks the cross-field rules of an Interaction (X-12, C-25).
///
/// # Errors
/// Names the first field that breaks a rule.
pub fn validate_interaction(i: &Interaction) -> Result<(), Invalid> {
    header_ok(i)?;
    localized(&i.subject.title, 60, "subject.title")?;
    check(
        i.subject.concerns.as_deref().is_none_or(|c| c.len() <= 8),
        "subject.concerns",
    )?;
    details_ok(&i.details)?;
    if let Some(p) = &i.presentation {
        check(
            p.catalog_version == CATALOG_VERSION,
            "presentation.catalog_version",
        )?;
        check(
            count_in(&p.components, 1, 12)
                && p.components.iter().all(|c| {
                    c.version >= 1
                        && c.binds
                            .as_deref()
                            .is_none_or(|b| b.len() <= 10 && unique(b))
                }),
            "presentation.components",
        )?;
    }
    check(
        !(i.data_class.is_sensitive() || i.data_class.kinds().contains(&DataKind::OneTimeCode))
            || i.sensitive,
        "sensitive",
    )?;
    localized(&i.why_now.reason, 200, "why_now.reason")?;
    check(i.why_now.evidence.len() <= 8, "why_now.evidence")?;
    check(
        (i.interruption == Interruption::Critical) == i.critical_grant.is_some(),
        "critical_grant",
    )?;
    check(
        match i.timing.delivery {
            Delivery::NextBreak => i.timing.max_defer.is_some(),
            Delivery::Immediate => i.timing.max_defer.is_none(),
        },
        "timing.max_defer",
    )?;
    check(
        i.timing.surface_policy.as_ref().is_none_or(|p| {
            count_in(&p.steps, 1, 5) && p.steps.iter().all(|s| count_in(&s.surfaces, 1, 8))
        }),
        "timing.surface_policy",
    )?;
    let m = &i.minimal_projection;
    localized(&m.sentence, 120, "minimal_projection.sentence")?;
    localized(&m.yes.label, 12, "minimal_projection.yes")?;
    localized(&m.no.label, 12, "minimal_projection.no")?;
    if let Some(t) = &i.surface_budgets.tighten {
        let classes: Vec<&ClassTighten> =
            SurfaceClass::ALL.iter().filter_map(|c| t.get(*c)).collect();
        check(
            !classes.is_empty() && classes.iter().all(|c| tighten_ok(c)),
            "surface_budgets.tighten",
        )?;
    }
    actions_ok(i)?;
    check(
        !i.min_assurance.surface_classes.is_empty() && unique(&i.min_assurance.surface_classes),
        "min_assurance.surface_classes",
    )?;
    kind_ok(i, i.kind.declared_core())
}

/// Checks the cross-field rules of an `InteractionResponse` (X-22, X-18, X-19, C-26).
///
/// # Errors
/// Names the first field that breaks a rule.
pub fn validate_response(r: &InteractionResponse) -> Result<(), Invalid> {
    check(r.interaction_version >= 1, "interaction_version")?;
    let e = &r.evidence;
    check(
        e.authentication != Authentication::Passkey
            || matches!(
                e.user_verification,
                UserVerification::Biometric | UserVerification::Pin
            ),
        "evidence.user_verification",
    )?;
    if r.surface_class.is_voice() {
        check(
            e.authentication != Authentication::Passkey
                && matches!(
                    e.presence_gesture,
                    Presence::Voice | Presence::Tap | Presence::None
                ),
            "evidence",
        )?;
    }
    check(
        r.surface_class != SurfaceClass::Watch || e.authentication != Authentication::Passkey,
        "evidence.authentication",
    )?;
    let sig = r.signature.cose_sign1.as_str();
    check(
        (86..=1400).contains(&sig.len())
            && sig
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "signature.cose_sign1",
    )
}
