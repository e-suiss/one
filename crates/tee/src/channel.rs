//! The client-to-TEE request channel (SEC-27, PV-11): a request is sealed with HPKE DHKEM(X25519) only to a node key that verified evidence binds through its `report_data`, with `info` naming the key's digest and the route as additional data; the response is one AES-256-GCM message under the request's HPKE export, bound to the request encapsulation.

use aws_lc_rs::aead::{
    AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, RandomizedNonceKey, UnboundKey,
};
use aws_lc_rs::digest::{SHA256, digest};
use one_hpke::{
    HpkeError, Kem, KeyPair, report_data, setup_receiver, setup_sender, setup_sender_with,
};
use zeroize::Zeroizing;

use crate::domain::attestation::{Evidence, Policy, Rejection, verify};

/// The HPKE `info` prefix of a request; the node key's SHA-256 follows.
pub const REQUEST_INFO: &[u8] = b"one/tee/request/v1\0";

/// The additional data prefix of a request route; the route name follows.
pub const ROUTE_AAD: &[u8] = b"one/tee/route/v1\0";

/// The HPKE exporter context of the response key, and the response's additional data prefix.
pub const RESPONSE_CONTEXT: &[u8] = b"one/tee/response/v1";

/// Why a request or response is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelError {
    /// The evidence does not admit the node.
    NotAttested(Rejection),
    /// HPKE failed: a foreign key, or a request that does not open.
    Hpke(HpkeError),
    /// A response does not open or seal.
    Response,
}

impl From<HpkeError> for ChannelError {
    fn from(e: HpkeError) -> Self {
        Self::Hpke(e)
    }
}

/// A node key that verified evidence binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedNode {
    public: Vec<u8>,
}

impl AttestedNode {
    /// Admits `public_key` when `evidence` carries its digest and passes `policy`; there is no other way to get a key to encrypt to.
    ///
    /// # Errors
    /// [`ChannelError::NotAttested`] with [`Rejection::ReportDataMismatch`] for another key, or the policy's first rejection.
    pub fn admit(
        public_key: &[u8],
        evidence: &Evidence,
        policy: &Policy<'_>,
    ) -> Result<Self, ChannelError> {
        let expected = report_data(public_key);
        if evidence.report_data != expected {
            return Err(ChannelError::NotAttested(Rejection::ReportDataMismatch));
        }
        let bound = Policy {
            expected_report_data: &expected,
            ..*policy
        };
        verify(evidence, &bound).map_err(ChannelError::NotAttested)?;
        Ok(Self {
            public: public_key.to_vec(),
        })
    }

    /// The node key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }
}

/// The request `info` for a node key: [`REQUEST_INFO`] and the key's SHA-256.
#[must_use]
pub fn request_info(public_key: &[u8]) -> Vec<u8> {
    let mut info = REQUEST_INFO.to_vec();
    info.extend_from_slice(digest(&SHA256, public_key).as_ref());
    info
}

/// The additional data of a request on `route`.
#[must_use]
pub fn route_aad(route: &str) -> Vec<u8> {
    let mut aad = ROUTE_AAD.to_vec();
    aad.extend_from_slice(route.as_bytes());
    aad
}

/// The key a response to one request is sealed under.
pub struct ResponseKey {
    key: Zeroizing<Vec<u8>>,
    aad: Vec<u8>,
}

impl ResponseKey {
    fn new(ctx: &one_hpke::Context, enc: &[u8]) -> Result<Self, ChannelError> {
        let key = ctx.export(RESPONSE_CONTEXT, 32)?;
        let mut aad = RESPONSE_CONTEXT.to_vec();
        aad.push(0);
        aad.extend_from_slice(enc);
        Ok(Self { key, aad })
    }

    /// A response key from its bytes and the request encapsulation.
    #[must_use]
    pub fn from_parts(key: &[u8], enc: &[u8]) -> Self {
        let mut aad = RESPONSE_CONTEXT.to_vec();
        aad.push(0);
        aad.extend_from_slice(enc);
        Self {
            key: Zeroizing::new(key.to_vec()),
            aad,
        }
    }

    /// The key bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.key
    }

    /// Seals the response under a fresh random nonce.
    ///
    /// # Errors
    /// [`ChannelError::Response`].
    pub fn seal(&self, plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>), ChannelError> {
        let key =
            RandomizedNonceKey::new(&AES_256_GCM, &self.key).map_err(|_| ChannelError::Response)?;
        let mut buf = plaintext.to_vec();
        let nonce = key
            .seal_in_place_append_tag(Aad::from(self.aad.as_slice()), &mut buf)
            .map_err(|_| ChannelError::Response)?;
        Ok((*nonce.as_ref(), buf))
    }

    /// Opens a response.
    ///
    /// # Errors
    /// [`ChannelError::Response`] for another request, key or a modified response.
    pub fn open(
        &self,
        nonce: [u8; NONCE_LEN],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ChannelError> {
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &self.key).map_err(|_| ChannelError::Response)?,
        );
        let mut buf = Zeroizing::new(ciphertext.to_vec());
        let len = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(self.aad.as_slice()),
                buf.as_mut_slice(),
            )
            .map_err(|_| ChannelError::Response)?
            .len();
        buf.truncate(len);
        Ok(buf)
    }
}

/// A sealed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The HPKE encapsulation.
    pub enc: Vec<u8>,
    /// The sealed request with its tag.
    pub ct: Vec<u8>,
}

fn seal_with_context(
    enc: Vec<u8>,
    mut ctx: one_hpke::Context,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Request, ResponseKey), ChannelError> {
    let ct = ctx.seal(aad, plaintext)?;
    let response = ResponseKey::new(&ctx, &enc)?;
    Ok((Request { enc, ct }, response))
}

/// Seals a request to an attested node; returns it with the key its response comes under.
///
/// # Errors
/// [`ChannelError::Hpke`].
pub fn seal_request(
    node: &AttestedNode,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Request, ResponseKey), ChannelError> {
    let (enc, ctx) = setup_sender(Kem::X25519, &node.public, &request_info(&node.public))?;
    seal_with_context(enc, ctx, aad, plaintext)
}

/// Seals a request with the given ephemeral key, which is never reused.
///
/// # Errors
/// [`ChannelError::Hpke`].
pub fn seal_request_with(
    ephemeral: &KeyPair,
    node: &AttestedNode,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Request, ResponseKey), ChannelError> {
    let (enc, ctx) = setup_sender_with(ephemeral, &node.public, &request_info(&node.public))?;
    seal_with_context(enc, ctx, aad, plaintext)
}

/// Opens a request inside the TEE with the node's key pair; returns the plaintext with the response key.
///
/// # Errors
/// [`ChannelError::Hpke`].
pub fn open_request(
    node: &KeyPair,
    request: &Request,
    aad: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, ResponseKey), ChannelError> {
    let public = node.public_key()?;
    let mut ctx = setup_receiver(node, &request.enc, &request_info(&public))?;
    let plaintext = ctx.open(aad, &request.ct)?;
    let response = ResponseKey::new(&ctx, &request.enc)?;
    Ok((plaintext, response))
}
