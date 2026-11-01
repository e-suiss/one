#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::format_collect,
    reason = "T-38"
)]

use serde_json::Value;

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fixed<const N: usize>(v: &Value) -> [u8; N] {
    unhex(v.as_str().unwrap()).try_into().unwrap()
}

fn shares(key: Scalar, xs: &[u64]) -> Vec<(u64, Scalar)> {
    let a1 = Scalar::from(0x0123_4567_89ab_cdef_u64);
    xs.iter()
        .map(|&x| (x, key + a1 * Scalar::from(x)))
        .collect()
}

// PV-12
#[test]
fn pv_12_oprf_vectors() {
    let path = format!(
        "{}/../conformance/recovery/vectors/oprf.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let all: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut rfc = 0;
    for v in &all {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        match input["op"].as_str().unwrap() {
            "rfc9497" => {
                let msg = unhex(input["input"].as_str().unwrap());
                let b = blind(&msg, Blind::Canonical(fixed(&input["blind"]))).unwrap();
                assert_eq!(
                    hex(&b.element),
                    expected["blinded_element"].as_str().unwrap(),
                    "{d}"
                );
                let e = evaluate(fixed(&input["skSm"]), &b.element).unwrap();
                assert_eq!(
                    hex(&e),
                    expected["evaluation_element"].as_str().unwrap(),
                    "{d}"
                );
                let out = finalize(&b, &e).unwrap();
                assert_eq!(hex(&*out), expected["output"].as_str().unwrap(), "{d}");
                let key = scalar(fixed(&input["skSm"])).unwrap();
                let realms = shares(key, &[1, 2, 3]);
                for pair in [[0, 1], [0, 2], [1, 2]] {
                    let evals: Vec<Evaluation> = pair
                        .iter()
                        .map(|&i| Evaluation {
                            x: realms[i].0,
                            element: evaluate(realms[i].1.to_bytes(), &b.element).unwrap(),
                        })
                        .collect();
                    let combined = combine(&evals, 2).unwrap();
                    assert_eq!(combined, e, "{d}");
                    assert_eq!(*finalize(&b, &combined).unwrap(), *out, "{d}");
                }
                rfc += 1;
            }
            "blind" => {
                let b = blind(&[7; 32], Blind::Wide([9; 64])).unwrap();
                assert_ne!(b.element.as_slice(), [7_u8; 32].as_slice(), "{d}");
                assert_eq!(expected["realm_sees_pin"], false, "{d}");
            }
            "combine" => {
                let key = Scalar::from(42_u64);
                let realms = shares(key, &[1, 2, 3]);
                let b = blind(b"access key", Blind::Wide([3; 64])).unwrap();
                let names = ["a", "b", "c"];
                let evals: Vec<Evaluation> = input["answered"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| {
                        let i = names
                            .iter()
                            .position(|x| *x == n.as_str().unwrap())
                            .unwrap();
                        Evaluation {
                            x: realms[i].0,
                            element: evaluate(realms[i].1.to_bytes(), &b.element).unwrap(),
                        }
                    })
                    .collect();
                let threshold = usize::try_from(input["threshold"].as_u64().unwrap()).unwrap();
                match combine(&evals, threshold) {
                    Ok(c) => {
                        assert_eq!(expected["combined"], true, "{d}");
                        assert_eq!(c, evaluate(key.to_bytes(), &b.element).unwrap(), "{d}");
                    }
                    Err(e) => assert_eq!(e.as_str(), expected["error"].as_str().unwrap(), "{d}"),
                }
            }
            "finalize" => {
                let b = blind(b"access key", Blind::Wide([5; 64])).unwrap();
                let identity = RistrettoPoint::identity().compress().to_bytes();
                assert_eq!(
                    finalize(&b, &identity).map(|_| ()).unwrap_err().as_str(),
                    expected["error"].as_str().unwrap(),
                    "{d}"
                );
            }
            op => panic!("{d}: unknown op {op}"),
        }
    }
    assert_eq!(rfc, 2);
}

#[test]
fn pv_12_a_repeated_realm_does_not_combine() {
    let b = blind(b"k", Blind::Wide([1; 64])).unwrap();
    let e = evaluate(Scalar::from(5_u64).to_bytes(), &b.element).unwrap();
    let twice = [
        Evaluation { x: 1, element: e },
        Evaluation { x: 1, element: e },
    ];
    assert_eq!(combine(&twice, 2), Err(OprfError::DuplicateX));
}
