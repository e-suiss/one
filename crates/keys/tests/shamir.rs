//! Every vector of `conformance/recovery/vectors/shamir.json`: 2-of-3 realm shares, the recovery contact's 2-of-2 with the account share, k-of-n contacts, and the refusals of a lone share, a zero coordinate and a repeated one (PV-12).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

mod common;

use common::{hex, load, unhex};
use one_keys::domain::shamir::{Share, combine, split};
use serde_json::Value;

fn shares(v: &Value) -> Vec<Share> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| Share {
            x: u8::try_from(s["x"].as_u64().unwrap()).unwrap(),
            y: unhex(s["y"].as_str().unwrap()),
        })
        .collect()
}

fn threshold(v: &Value) -> u8 {
    v.as_u64().map_or(2, |t| u8::try_from(t).unwrap())
}

#[test]
fn pv_12_shamir_vectors() {
    let all = load("recovery/vectors/shamir.json");
    for v in &all {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        let secret = input["secret"].as_str().map(unhex);
        match input["op"].as_str().unwrap() {
            "split" => {
                let xs: Vec<u8> = input["xs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| u8::try_from(x.as_u64().unwrap()).unwrap())
                    .collect();
                let k = threshold(&input["threshold"]);
                let coefficients: Vec<Vec<u8>> = input["coefficients"].as_array().map_or_else(
                    || vec![vec![0; 32]; usize::from(k).saturating_sub(1)],
                    |c| c.iter().map(|c| unhex(c.as_str().unwrap())).collect(),
                );
                match split(&secret.clone().unwrap(), k, &xs, &coefficients) {
                    Ok(got) => {
                        assert_eq!(got, shares(&expected["shares"]), "{d}");
                        let first: Vec<Share> = got.iter().take(usize::from(k)).cloned().collect();
                        assert_eq!(combine(&first, k).unwrap(), secret.clone().unwrap(), "{d}");
                        let last: Vec<Share> =
                            got.iter().rev().take(usize::from(k)).cloned().collect();
                        assert_eq!(combine(&last, k).unwrap(), secret.unwrap(), "{d}");
                        if got.len() > usize::from(k) || k == 2 {
                            let short: Vec<Share> = got
                                .iter()
                                .take(usize::from(k).saturating_sub(1))
                                .cloned()
                                .collect();
                            assert!(combine(&short, k).is_err(), "{d}");
                        }
                    }
                    Err(e) => assert_eq!(e.as_str(), expected["error"].as_str().unwrap(), "{d}"),
                }
            }
            "combine" => match combine(&shares(&input["shares"]), threshold(&input["threshold"])) {
                Ok(got) => {
                    assert_eq!(hex(&got), expected["secret"].as_str().unwrap(), "{d}");
                }
                Err(e) => assert_eq!(e.as_str(), expected["error"].as_str().unwrap(), "{d}"),
            },
            op => panic!("{d}: unknown op {op}"),
        }
    }
    assert_eq!(all.len(), 9);
}
