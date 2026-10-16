//! JSON-RPC 2.0 responses as MCP and A2A carry them: one identifier and exactly one of a result or an error.

use alloc::string::String;

use one_proto::ontology::JsonValue;
use serde::Deserialize;
use serde::de::{self, Deserializer};

/// A request identifier.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum RpcId {
    /// An integer identifier.
    Number(i64),
    /// A string identifier.
    Text(String),
    /// `null`, sent when the request could not be read.
    Null,
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RpcError {
    /// The error code.
    pub code: i64,
    /// The error message.
    pub message: String,
    /// Additional data.
    #[serde(default)]
    pub data: Option<JsonValue>,
}

/// The outcome of a call.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome<T> {
    /// The `result` member.
    Result(T),
    /// The `error` member.
    Error(RpcError),
}

/// A JSON-RPC 2.0 response; unknown members are ignored.
#[derive(Debug, Clone, PartialEq)]
pub struct Response<T> {
    /// The identifier of the answered request.
    pub id: RpcId,
    /// The result or error.
    pub outcome: Outcome<T>,
}

#[derive(Deserialize)]
enum Version {
    #[serde(rename = "2.0")]
    V2,
}

#[derive(Deserialize)]
#[serde(bound = "T: Deserialize<'de>")]
struct Raw<T> {
    #[serde(rename = "jsonrpc")]
    _version: Version,
    id: RpcId,
    #[serde(default = "none")]
    result: Option<T>,
    #[serde(default)]
    error: Option<RpcError>,
}

const fn none<T>() -> Option<T> {
    None
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Response<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Raw::<T>::deserialize(d)?;
        let outcome = match (raw.result, raw.error) {
            (Some(result), None) => Outcome::Result(result),
            (None, Some(error)) => Outcome::Error(error),
            _ => return Err(de::Error::custom("exactly one of result and error")),
        };
        Ok(Self {
            id: raw.id,
            outcome,
        })
    }
}
