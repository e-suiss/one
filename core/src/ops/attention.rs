//! Attention operations: the decision head route and the Relay mapping of an output (AT-1, AT-2, AT-9, AT-12, AT-42).

use one_proto::attention::{
    HeadInput, Probability, RelayCandidate, Route, Thresholds, decide as head, map_to_relay,
};
use one_proto::interaction_types::Interruption;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::{object, parse, wire};
use crate::CoreError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools, reason = "AT-1")]
struct DecideInput {
    value_probability: Probability,
    thresholds: Thresholds,
    urgent: bool,
    cloud_available: bool,
    type_muted: bool,
    budget_remaining: u8,
    critical_grant: bool,
}

pub(super) fn decide(input: Value) -> Result<Value, CoreError> {
    let i: DecideInput = parse(input, "decision head input")?;
    let decision = head(&HeadInput {
        value_probability: i.value_probability,
        thresholds: i.thresholds,
        urgent: i.urgent,
        cloud_available: i.cloud_available,
        type_muted: i.type_muted,
        budget_remaining: i.budget_remaining,
        critical_grant: i.critical_grant,
    });
    let d = match decision {
        Ok(d) => d,
        Err(e) => return Ok(object([("rejected", Value::from(e.0))])),
    };
    let route = match d.route {
        Route::Notify => "notify",
        Route::NoNotification => "no_notification",
        Route::CloudEstimate => "cloud_estimate",
    };
    let mut m = Map::new();
    m.insert("route".to_owned(), Value::from(route));
    if let Some(arm) = d.chosen_arm {
        m.insert("chosen_arm".to_owned(), wire(&arm)?);
    }
    if let Some(level) = d.interruption {
        m.insert("interruption".to_owned(), wire(&level)?);
    }
    Ok(Value::Object(m))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools, reason = "AT-42")]
struct RelayInput {
    output_type: String,
    interruption: Interruption,
    urgent: bool,
    critical_grant: bool,
    personal_agent_registered: bool,
}

pub(super) fn relay_mapping(input: Value) -> Result<Value, CoreError> {
    let i: RelayInput = parse(input, "relay candidate")?;
    let sent = map_to_relay(&RelayCandidate {
        output_type: &i.output_type,
        interruption: i.interruption,
        urgent: i.urgent,
        critical_grant: i.critical_grant,
        personal_agent_registered: i.personal_agent_registered,
    });
    let Some(s) = sent else {
        return Ok(object([("send", Value::Bool(false))]));
    };
    Ok(object([
        ("send", Value::Bool(true)),
        ("relay_class", wire(&s.relay_class)?),
        ("interruption", wire(&s.interruption)?),
        ("timing", wire(&s.timing)?),
        ("max_defer_required", Value::Bool(s.max_defer_required)),
    ]))
}
