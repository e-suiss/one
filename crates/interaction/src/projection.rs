//! The projection decision: for an Interaction, a surface class and a target, the first rule of the fixed order decides full, minimal, neutral, redirect or none; a pure function of its inputs (X-13, X-4, X-6, X-10, X-19, X-20, X-36, X-45, X-46, T-27 (4)).

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use one_proto::data_class::DataKind;
use one_proto::ontology::{OwnerId, Target};
use serde::Serialize;

use crate::budget::{
    MINIMAL, ORDER, ProjectionOutcome, Rule, SENSITIVE_VOICE_TARGETS, TargetBudget,
};
use crate::common::{CoreKind, Locale, MandateFit, chars};
use crate::interaction::{Interaction, Visuals};
use crate::json_size::Json;
use crate::kind::Kind;
use crate::surface::{ClassRow, SurfaceTarget};
use one_proto::interaction_types::SurfaceClass;

/// The decision for one target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Projection {
    /// What is sent.
    pub projection: ProjectionOutcome,
    /// The rule that decided.
    pub reason: Rule,
    /// Canonical JSON bytes of the Live Activity payload, larger locale, when measured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projected_bytes: Option<usize>,
}

/// True if the Interaction may carry its sensitive marking: the flag, a PV-20 class or a one-time code (X-20).
#[must_use]
pub fn is_sensitive(i: &Interaction) -> bool {
    i.sensitive
        || i.data_class.is_sensitive()
        || i.data_class.kinds().contains(&DataKind::OneTimeCode)
}

/// True if an approval can be given on this class: within the class ceiling, the Interaction's own minimum assurance and the user's tightening (X-19, A-28).
#[must_use]
pub fn approval_within_ceiling(i: &Interaction, class: SurfaceClass) -> bool {
    let fit = i.mandate_fit.unwrap_or(MandateFit::Within);
    let direct_only = i.min_assurance.direct_act_only == Some(true)
        && !matches!(class, SurfaceClass::Phone | SurfaceClass::Desktop);
    let tightened = i.tighten(class).and_then(|t| t.no_approval) == Some(true);
    class.ceiling().admits(i.risk, i.reversibility, fit)
        && i.min_assurance.surface_classes.contains(&class)
        && !direct_only
        && !tightened
}

fn id_text(target: &Target) -> Option<String> {
    match target {
        Target::Record(r) => Some(alloc::format!("{}", r.id)),
        Target::Any(a) => a.owner_id().map(|id| String::from(id.as_str())),
    }
}

fn text(s: &str) -> Json<'_> {
    Json::Str(Cow::Borrowed(s))
}

fn kind_json(kind: &Kind) -> Json<'_> {
    match kind {
        Kind::Core(k) => text(k.as_str()),
        Kind::Extension(e) => Json::Object(vec![
            ("extension", text(e.extension.as_str())),
            ("version", Json::UInt(u64::from(e.version))),
            ("maps_to", text(e.maps_to.as_str())),
        ]),
    }
}

/// The Live Activity `{attributes, content_state}` payload of the full projection in one locale (`projection/live-activity.toml`).
#[must_use]
pub fn live_activity_payload(i: &Interaction, locale: Locale) -> Json<'_> {
    let task = id_text(&i.subject.reference).unwrap_or_default();
    let attributes = Json::Object(vec![
        (
            "interaction_id",
            Json::Str(Cow::Owned(alloc::format!("{}", i.id))),
        ),
        ("task", Json::Str(Cow::Owned(task))),
        ("kind", kind_json(&i.kind)),
    ]);
    let mut state = vec![
        ("version", Json::UInt(u64::from(i.version))),
        ("title", text(i.subject.title.get(locale))),
        ("status", text(i.minimal_projection.sentence.get(locale))),
    ];
    if let Some(p) = &i.details.progress {
        state.push(("phase", text(phase_name(p.phase))));
        if let Some(f) = p.fraction {
            state.push(("fraction", Json::Number(f)));
        }
        if let Some(s) = &p.step_label {
            state.push(("step", text(s)));
        }
    }
    if let Some(steps) = &i.details.steps {
        state.push((
            "steps",
            Json::Array(
                steps
                    .iter()
                    .map(|s| {
                        Json::Object(vec![
                            ("label", text(&s.label)),
                            ("status", text(s.status.as_str())),
                        ])
                    })
                    .collect(),
            ),
        ));
    }
    if let Some(link) = &i.deep_link {
        state.push(("deep_link", text(link.as_str())));
    }
    Json::Object(vec![
        ("attributes", attributes),
        ("content_state", Json::Object(state)),
    ])
}

const fn phase_name(p: crate::interaction::Phase) -> &'static str {
    use crate::interaction::Phase;
    match p {
        Phase::Starting => "starting",
        Phase::InProgress => "in_progress",
        Phase::Waiting => "waiting",
        Phase::Stopping => "stopping",
        Phase::Finished => "finished",
        Phase::Unknown => "unknown",
    }
}

/// Canonical JSON bytes of the Live Activity payload; the larger locale decides (X-13, X-6).
#[must_use]
pub fn live_activity_bytes(i: &Interaction) -> usize {
    Locale::ALL
        .iter()
        .map(|l| live_activity_payload(i, *l).canonical_len())
        .max()
        .unwrap_or(0)
}

/// The Android Live Update chip: the step label when it fits, else the percentage (`projection/live-update.toml`).
#[must_use]
pub fn live_update_chip(i: &Interaction, max_chars: usize) -> Option<String> {
    let p = i.details.progress.as_ref()?;
    if let Some(label) = p.step_label.as_deref().filter(|l| chars(l) <= max_chars) {
        return Some(String::from(label));
    }
    let f = p.fraction?;
    let mut percent = 0_u32;
    while percent < 100 && f64::from(percent.saturating_add(1)) <= f * 100.0 {
        percent = percent.saturating_add(1);
    }
    Some(alloc::format!("{percent}%")).filter(|c| chars(c) <= max_chars)
}

fn limit(table: Option<u32>, tightened: Option<u32>) -> Option<usize> {
    let pick = match (table, tightened) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    pick.and_then(|v| usize::try_from(v).ok())
}

fn within(value: usize, max: Option<usize>) -> bool {
    max.is_none_or(|m| value <= m)
}

fn spoken_chars(i: &Interaction, kind: CoreKind, locale: Locale) -> usize {
    let title = chars(i.subject.title.get(locale));
    let body = match (kind, i.details.options.as_deref()) {
        (CoreKind::Choice, Some(options)) => options.iter().fold(0_usize, |n, o| {
            n.saturating_add(chars(&o.title)).saturating_add(2)
        }),
        _ => chars(i.minimal_projection.sentence.get(locale)).saturating_add(2),
    };
    title.saturating_add(body)
}

fn list_items(i: &Interaction, kind: CoreKind) -> Vec<&str> {
    match kind {
        CoreKind::Choice | CoreKind::Comparison => i
            .details
            .options
            .iter()
            .flatten()
            .map(|o| o.title.as_str())
            .collect(),
        _ => i
            .details
            .steps
            .iter()
            .flatten()
            .map(|s| s.label.as_str())
            .collect(),
    }
}

/// True if the full projection fits the target budget and the class tightening; also returns the measured Live Activity bytes (X-13).
#[must_use]
pub fn fits_budget(
    i: &Interaction,
    kind: CoreKind,
    class: SurfaceClass,
    target: SurfaceTarget,
) -> (bool, Option<usize>) {
    let b: &TargetBudget = target.budget();
    let t = i.tighten(class);
    let title_max = limit(b.max_title_chars, t.and_then(|t| t.max_title_chars));
    let body_max = limit(
        b.max_body_chars.or(b.max_status_chars),
        t.and_then(|t| t.max_body_chars),
    );
    let actions_max = limit(
        b.max_actions.or(b.max_buttons),
        t.and_then(|t| t.max_actions),
    );
    let text_only = t.and_then(|t| t.visuals) == Some(Visuals::TextOnly);
    let options = i.details.options.as_ref().map_or(0, Vec::len);
    let presence = target != SurfaceTarget::Workspace;
    let shown_actions = if !presence {
        i.actions.len()
    } else if b.passive_only == Some(true) {
        limit(Some(MINIMAL.passive_answers), None).unwrap_or(1)
    } else {
        limit(Some(MINIMAL.answers), None).unwrap_or(2)
    };
    let mut ok = within(i.subject.title.max_chars(), title_max)
        && within(i.minimal_projection.sentence.max_chars(), body_max)
        && within(shown_actions, actions_max);
    let mut bytes = None;
    match target {
        SurfaceTarget::Workspace => {
            let components = i.presentation.as_ref().map_or(0, |p| p.components.len());
            let fields = i.details.fields.as_ref().map_or(0, Vec::len);
            let option_max = match kind {
                CoreKind::Choice => limit(b.max_choice_options, None),
                CoreKind::Comparison => limit(b.max_comparison_options, None),
                _ => None,
            };
            ok = ok
                && within(components, limit(b.max_components, None))
                && within(options, option_max)
                && within(fields, limit(b.max_form_fields, None));
        }
        SurfaceTarget::LiveActivity => {
            let measured = live_activity_bytes(i);
            bytes = Some(measured);
            ok = ok && within(measured, limit(b.max_bytes, None));
        }
        SurfaceTarget::CarVoice | SurfaceTarget::GlassesVoice => {
            let spoken = Locale::ALL
                .iter()
                .map(|l| spoken_chars(i, kind, *l))
                .max()
                .unwrap_or(0);
            let spoken_options = if kind == CoreKind::Choice { options } else { 2 };
            ok = ok
                && within(spoken, limit(b.max_spoken_chars, None))
                && within(spoken_options, limit(b.max_spoken_options, None));
        }
        SurfaceTarget::GlassesDisplay => {
            let items = list_items(i, kind);
            let images = i
                .details
                .options
                .iter()
                .flatten()
                .filter(|o| o.image.is_some())
                .count();
            let image_max = if text_only {
                Some(0)
            } else {
                limit(b.max_images, None)
            };
            ok = ok
                && within(items.len(), limit(b.max_list_items, None))
                && items
                    .iter()
                    .all(|s| within(chars(s), limit(b.max_list_item_chars, None)))
                && within(images, image_max);
        }
        SurfaceTarget::Complication => {
            ok = ok && within(i.subject.title.max_chars(), limit(b.max_chars, None));
        }
        SurfaceTarget::Notification
        | SurfaceTarget::LiveUpdate
        | SurfaceTarget::Widget
        | SurfaceTarget::MenuBar
        | SurfaceTarget::WatchApp => {}
    }
    (ok, bytes)
}

fn applies(
    rule: Rule,
    i: &Interaction,
    kind: CoreKind,
    class: SurfaceClass,
    target: SurfaceTarget,
    declared: &[SurfaceTarget],
    bytes: &mut Option<usize>,
) -> bool {
    let b = target.budget();
    match rule {
        Rule::UndeclaredTarget => {
            !declared.contains(&target) || !class.has_target(target) || !b.class.contains(&class)
        }
        Rule::SensitiveOnVoice => SENSITIVE_VOICE_TARGETS.contains(&target) && is_sensitive(i),
        Rule::ApprovalAboveCeiling => {
            kind == CoreKind::Approval && !approval_within_ceiling(i, class)
        }
        Rule::KindNotOnTarget => !b.kinds.contains(&kind),
        Rule::AlwaysMinimal => b.always_minimal == Some(true),
        Rule::OverBudget => {
            let (ok, measured) = fits_budget(i, kind, class, target);
            *bytes = measured;
            !ok
        }
        Rule::Fits => true,
    }
}

/// Decides the projection of `i` (whose kind resolved to `kind`) on `target` of `class`, given the targets the device declared (X-13).
#[must_use]
pub fn project(
    i: &Interaction,
    kind: CoreKind,
    class: SurfaceClass,
    target: SurfaceTarget,
    declared: &[SurfaceTarget],
) -> Projection {
    let mut bytes = None;
    let reason = ORDER
        .iter()
        .copied()
        .find(|r| applies(*r, i, kind, class, target, declared, &mut bytes))
        .unwrap_or(Rule::Fits);
    Projection {
        projection: reason.outcome(),
        reason,
        projected_bytes: bytes,
    }
}
