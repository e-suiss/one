//! The key layer: the OP-4 wrap and seal of record keys, class DEKs and record parts in [`seal`], the KEK's device and passkey copies in [`device`], the DEK hand-over to an attested TEE job key in [`job_key`], the device Instance signature check in [`instance`], server key access through PKCS#11 in [`hsm`], and the pure rules of time-bound key permission admission and its COSE form, PIN vault guess limits and threshold coordination, and retention expiry; signature checks, Access state and key operations come in through [`ports`] (OP-4, PV-12, PV-16, PV-65, T-27 (1, 2)).

pub mod app;
pub mod device;
pub mod domain;
pub mod hsm;
pub mod instance;
pub mod job_key;
pub mod ports;
pub mod seal;
