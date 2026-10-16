//! The join is commutative, associative and idempotent over every label, never improves trust, and labelled values never show their content (INV-15, SEC-14 (1), T-28 (7), T-36).

#![allow(
    clippy::unwrap_used,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use one_provenance::confirm::{SecondEvidence, ShownConfirmation, Surface, Target, corroborate};
use one_provenance::{
    ExternalSource, Label, LabelKind, Labelled, MixedSources, PlannerContext, Transform, Trusted,
    TrustedLabel, Untrusted, UntrustedLabel, VarRef, VariableTable,
};

fn universe() -> Vec<Label> {
    let mut all: Vec<Label> = LabelKind::ALL.iter().filter_map(|k| k.single()).collect();
    let ext = ExternalSource::ALL;
    for (i, a) in ext.iter().enumerate() {
        for b in &ext[i + 1..] {
            all.push(Label::Untrusted(UntrustedLabel::Mixed(
                MixedSources::new([*a, *b]).unwrap(),
            )));
        }
    }
    for triple in [
        [
            ExternalSource::Email,
            ExternalSource::Web,
            ExternalSource::One,
        ],
        [
            ExternalSource::Unknown,
            ExternalSource::ToolOutput,
            ExternalSource::Agent,
        ],
    ] {
        all.push(Label::Untrusted(UntrustedLabel::Mixed(
            MixedSources::new(triple).unwrap(),
        )));
    }
    all
}

#[test]
fn inv_15_join_is_idempotent() {
    for a in universe() {
        assert_eq!(a.join(&a), a);
    }
}

#[test]
fn inv_15_join_is_commutative() {
    let all = universe();
    for a in &all {
        for b in &all {
            assert_eq!(a.join(b), b.join(a));
        }
    }
}

#[test]
fn inv_15_join_is_associative() {
    let all = universe();
    for a in &all {
        for b in &all {
            let ab = a.join(b);
            for c in &all {
                assert_eq!(ab.join(c), a.join(&b.join(c)));
            }
        }
    }
}

#[test]
fn inv_15_join_never_improves_trust() {
    let all = universe();
    for a in &all {
        for b in &all {
            let j = a.join(b);
            assert_eq!(j.rank(), a.rank().min(b.rank()));
            assert_eq!(j.is_trusted(), a.is_trusted() && b.is_trusted());
            if let Label::Untrusted(u) = &j {
                for s in [a, b] {
                    if let Label::Untrusted(x) = s {
                        for e in x.external_sources() {
                            assert!(u.external_sources().contains(e));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn sec_14_transforms_never_clear_a_label() {
    let all = universe();
    let transforms = [
        Transform::Combine,
        Transform::Summarise,
        Transform::Translate,
        Transform::QuarantineExtract,
        Transform::NormaliseText,
        Transform::MemoryWrite,
    ];
    for a in &all {
        for t in transforms {
            let derived = t.label([a]).unwrap();
            assert!(derived.rank() <= a.rank());
            assert_eq!(derived.is_trusted(), a.is_trusted());
        }
    }
    assert!(Transform::Summarise.label([]).is_none());
}

#[test]
fn t_36_label_strings_round_trip() {
    for k in LabelKind::ALL {
        assert_eq!(LabelKind::parse(k.as_str()), Some(k));
        assert_eq!(serde_json::to_value(k).unwrap(), k.as_str());
        let back: LabelKind = serde_json::from_value(serde_json::to_value(k).unwrap()).unwrap();
        assert_eq!(back, k);
    }
    let mut names: Vec<&str> = ExternalSource::ALL.iter().map(|e| e.as_str()).collect();
    let sorted = {
        let mut s = names.clone();
        s.sort_unstable();
        s
    };
    assert_eq!(names, sorted);
    names.dedup();
    assert_eq!(names.len(), 14);
}

#[test]
fn t_36_mixed_needs_two_different_sources() {
    assert!(MixedSources::new([ExternalSource::Web]).is_none());
    assert!(MixedSources::new([ExternalSource::Web, ExternalSource::Web]).is_none());
    let m = MixedSources::new([ExternalSource::Web, ExternalSource::Email]).unwrap();
    assert_eq!(m.as_slice(), &[ExternalSource::Email, ExternalSource::Web]);
}

#[test]
fn t_28_labelled_values_mask_their_content() {
    let trusted = Trusted::user_direct("Ayşe'ye yarın ara");
    let untrusted = Untrusted::external("ayse@example.com", ExternalSource::Email);
    let t = format!("{trusted:?}");
    let u = format!("{untrusted:?}");
    let l = format!("{:?}", Labelled::from(untrusted.clone()));
    for (shown, secret) in [(&t, "Ayşe"), (&u, "ayse@"), (&l, "ayse@")] {
        assert!(!shown.contains(secret), "{shown}");
        assert!(shown.contains("[masked]"), "{shown}");
    }
    assert!(u.contains("external.email"));
    let mut table = VariableTable::new();
    let var = table.bind(untrusted).unwrap();
    assert!(!format!("{table:?}").contains("ayse@"));
    assert_eq!(var.to_string(), "var_1");
}

#[test]
fn t_36_only_confirmation_makes_untrusted_trusted() {
    let value = Untrusted::external("ayse@example.com", ExternalSource::Email);
    assert!(ShownConfirmation::new(Surface::Chat, true, Target::Memory).is_none());
    assert!(ShownConfirmation::new(Surface::TrustedSurface, false, Target::Memory).is_none());
    let proof = ShownConfirmation::new(Surface::TrustedSurface, true, Target::Memory).unwrap();
    let (trusted, record) = proof.confirm(value.clone()).into_parts();
    assert_eq!(trusted.label(), TrustedLabel::UserMemory);
    assert_eq!(record.from(), LabelKind::External(ExternalSource::Email));
    assert_eq!(*trusted.expose(), "ayse@example.com");
    let inferred = corroborate(value.clone(), SecondEvidence::Independent);
    assert_eq!(*inferred.label(), UntrustedLabel::OneInferred);
    let again = corroborate(inferred, SecondEvidence::Independent);
    assert_eq!(*again.label(), UntrustedLabel::OneInferred);
    assert_eq!(
        *corroborate(value, SecondEvidence::SameSource).label(),
        UntrustedLabel::External(ExternalSource::Email)
    );
}

#[test]
fn t_36_planner_context_reads_trusted_content_and_references() {
    let mut table = VariableTable::new();
    let var = table
        .bind(Untrusted::external(
            "ayse@example.com",
            ExternalSource::Email,
        ))
        .unwrap();
    let mut context = PlannerContext::new();
    assert_eq!(context.literal_label(), None);
    context.push_trusted(Trusted::user_direct("Selam"));
    context.push_trusted(Trusted::record("48500.00"));
    context.push_variable(&table, var);
    assert_eq!(context.literal_label(), Some(TrustedLabel::RecordTrusted));
    assert_eq!(context.variables().len(), 1);
    assert_eq!(
        context.variables()[0].1,
        Label::Untrusted(UntrustedLabel::External(ExternalSource::Email))
    );
}

#[test]
fn t_36_memory_write_of_user_input_is_user_memory() {
    let v = Trusted::user_direct("Americano").into_memory();
    assert_eq!(v.label(), TrustedLabel::UserMemory);
    assert_eq!(
        Trusted::record("x").into_memory().label(),
        TrustedLabel::RecordTrusted
    );
}

#[test]
fn t_36_variable_references_are_canonical() {
    for ok in ["var_0", "var_1", "var_999999"] {
        let v = VarRef::parse(ok).unwrap();
        assert_eq!(v.to_string(), ok);
        assert_eq!(serde_json::to_value(v).unwrap(), ok);
    }
    for bad in [
        "var_",
        "var_1000000",
        "var_01",
        "VAR_1",
        "var_-1",
        "var_1a",
        "x_1",
    ] {
        assert!(VarRef::parse(bad).is_none(), "{bad}");
    }
}
