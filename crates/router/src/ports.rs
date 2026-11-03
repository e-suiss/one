//! The router's ports: the serving instances with their health, and the store that keeps routing records split into their `one_memory` and `one_provider_trace` parts (MF-22, SEC-27).

use std::future::Future;

use one_proto::model::routing::RoutingRecord;

use crate::domain::gate::Instance;

/// The serving instances of the user's region and their health, joined with the model registry.
pub trait Serving {
    /// Every instance, default family first in preference order.
    fn instances(&mut self) -> impl Future<Output = Vec<Instance>>;
}

/// Why a routing record was not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordError {
    /// The store failed; the request is not served without its record.
    Store,
}

/// Keeps routing records in the router layer; serving nodes keep none (SEC-27).
pub trait Records {
    /// Keeps `record`, its two parts in their own retention classes.
    fn keep(&mut self, record: RoutingRecord) -> impl Future<Output = Result<(), RecordError>>;
}
