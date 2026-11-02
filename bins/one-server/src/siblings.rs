//! The sibling watch (E-2, T-23, T-40 (7)): Access, Relay and Work are checked on a fixed period and every change of state is logged, an unreachable sibling as a `sibling.unreachable` alarm; it never makes the process unready.

use std::time::Duration;

use one_config::Siblings;

const TIMEOUT: Duration = Duration::from_secs(5);
const PERIOD: Duration = Duration::from_secs(30);

async fn check(
    client: &reqwest::Client,
    siblings: &Siblings,
    name: &str,
) -> Result<(), &'static str> {
    match name {
        "access" => one_access_client::fetch::discover(client, &siblings.access)
            .await
            .map(|_| ())
            .map_err(one_access_client::fetch::FetchError::as_str),
        "relay" => one_relay_client::ready(client, &siblings.relay)
            .await
            .map_err(one_relay_client::Unreachable::as_str),
        _ => one_work_client::reachable(client, &siblings.work)
            .await
            .map_err(one_work_client::Unreachable::as_str),
    }
}

/// Watches the siblings until the process stops.
///
/// # Errors
/// The HTTP client could not be built.
pub(crate) fn watch(siblings: Siblings) -> Result<impl Future<Output = ()>, reqwest::Error> {
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    Ok(async move {
        let mut last: [Option<bool>; 3] = [None; 3];
        let mut tick = tokio::time::interval(PERIOD);
        loop {
            tick.tick().await;
            for (slot, (name, _)) in last.iter_mut().zip(siblings.all()) {
                let result = check(&client, &siblings, name).await;
                if *slot == Some(result.is_ok()) {
                    continue;
                }
                *slot = Some(result.is_ok());
                match result {
                    Ok(()) => {
                        tracing::info!(event = "sibling.reachable", outcome = "ok", sibling = name)
                    }
                    Err(reason) => tracing::error!(
                        event = "sibling.unreachable",
                        outcome = "error",
                        sibling = name,
                        reason
                    ),
                }
            }
        }
    })
}
