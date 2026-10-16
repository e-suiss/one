//! Calibration of the decision head: the reliability curve over 10 equal-width bins (the last bin closed) and the expected calibration error gate ECE ≤ 0.05 (AT-1, AT-24; OD-63 #2).

use alloc::vec::Vec;

use super::record::Probability;

/// The number of equal-width bins.
pub const BINS: usize = 10;

/// The highest expected calibration error that passes the gate (OD-63 #2).
pub const ECE_GATE: f64 = 0.05;

/// A recorded prediction and whether the output turned out worth it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Prediction {
    /// The predicted probability.
    pub probability: Probability,
    /// The observed outcome.
    pub outcome: bool,
}

/// One non-empty bin of the reliability curve.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Bin {
    /// The bin index, 0 for `[0, 0.1)` to 9 for `[0.9, 1]`.
    pub bin: usize,
    /// Predictions in the bin.
    pub count: usize,
    /// Their mean probability.
    pub mean_probability: f64,
    /// Their observed rate.
    pub observed_rate: f64,
}

fn as_f64(n: usize) -> f64 {
    u32::try_from(n).map_or(f64::from(u32::MAX), f64::from)
}

/// The bin of a probability: `[k/10, (k+1)/10)`, the last bin closed.
#[must_use]
pub fn bin_of(p: Probability) -> usize {
    let scaled = p.get() * 10.0;
    (1..BINS).filter(|&k| scaled >= as_f64(k)).count()
}

/// The reliability curve: the non-empty bins in order.
#[must_use]
pub fn reliability_curve(predictions: &[Prediction]) -> Vec<Bin> {
    (0..BINS)
        .filter_map(|bin| {
            let members = || {
                predictions
                    .iter()
                    .filter(move |p| bin_of(p.probability) == bin)
            };
            let count = members().count();
            if count == 0 {
                return None;
            }
            let n = as_f64(count);
            Some(Bin {
                bin,
                count,
                mean_probability: members().map(|p| p.probability.get()).sum::<f64>() / n,
                observed_rate: as_f64(members().filter(|p| p.outcome).count()) / n,
            })
        })
        .collect()
}

/// The expected calibration error; `None` without predictions.
#[must_use]
pub fn expected_calibration_error(predictions: &[Prediction]) -> Option<f64> {
    if predictions.is_empty() {
        return None;
    }
    let total = as_f64(predictions.len());
    Some(
        reliability_curve(predictions)
            .iter()
            .map(|b| as_f64(b.count) / total * (b.mean_probability - b.observed_rate).abs())
            .sum(),
    )
}

/// True when the head is calibrated enough to ship: ECE ≤ [`ECE_GATE`].
#[must_use]
pub fn passes_calibration_gate(predictions: &[Prediction]) -> bool {
    expected_calibration_error(predictions).is_some_and(|ece| ece <= ECE_GATE)
}
