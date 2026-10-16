//! Attention decision records, output types and the Relay class mapping (AT-1, AT-42).

pub mod calibration;
pub mod catalog;
pub mod head;
pub mod record;

pub use calibration::{
    BINS, Bin, ECE_GATE, Prediction, expected_calibration_error, passes_calibration_gate,
    reliability_curve,
};
pub use catalog::{
    OUTPUT_TYPES, OneRelayClass, OutputType, RELAY_ROWS, RelayCandidate, RelaySend, RowId, Timing,
    clamp_to_ceiling, map_to_relay, output_type,
};
pub use head::{HeadDecision, HeadInput, Route, decide};
pub use record::{Arm, DecisionRecord, Probability, Propensity, Thresholds};
