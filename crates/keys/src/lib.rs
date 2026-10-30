//! The key layer's pure rules: time-bound key permission admission and its COSE form, PIN vault guess limits and threshold coordination, and retention expiry; signature checks, Access state and key operations come in through [`ports`] (OP-4, PV-12, PV-16, PV-65, T-27 (1, 2)).

pub mod app;
pub mod domain;
pub mod ports;
