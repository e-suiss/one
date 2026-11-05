//! The path and place of a step (CP-9, CP-12, CP-13, CP-14, T-22): the first offer that exists and works in the fixed order (official API, MCP server or commerce protocol, then an OS intent, then the self-identifying cloud browser), and the user when none does; an OS intent runs only on Android, an `AppFunction` only when One allowlists it, and never on iOS; a site whose terms forbid agents, or that blocks the agent, is handed to the user and never used in disguise; the place follows from the path and from whether the step needs the user's session and the user is there, never from the model.

use one_proto::capability::PathType;
use one_proto::ontology::validate::ContractViolation;
use one_proto::task::{Route, RouteLocation, RoutePath, RouteReason};

/// The platform an OS intent would run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Android: intents and allowlisted `AppFunctions`.
    Android,
    /// iOS: One drives no other app (CP-13).
    Ios,
    /// A desktop: no OS intent path to other apps.
    Desktop,
    /// No device is online.
    Offline,
}

/// One provider's way to do the step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools, reason = "CP-12")]
pub struct Offer {
    /// How the provider is reached.
    pub path: PathType,
    /// Whether it works now: its evaluation passed and the provider is healthy (CP-19).
    pub working: bool,
    /// An OS intent that is an Android `AppFunction`.
    pub app_function: bool,
    /// Whether One allowlists that `AppFunction`.
    pub allowlisted: bool,
}

/// What the site of a browser offer says about agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Site {
    /// Its terms of service forbid AI agents (CP-14).
    pub terms_forbid_agents: bool,
    /// It blocks the agent.
    pub blocks_agents: bool,
}

/// Where the step stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Situation {
    /// The platform of the user's device.
    pub platform: Platform,
    /// The step needs the user's own session.
    pub needs_session: bool,
    /// The user is at the device.
    pub user_present: bool,
}

/// Why the step goes to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handoff {
    /// No offer exists or works.
    NoPath,
    /// The site's terms forbid agents (CP-14).
    TermsForbidAgents,
    /// The site blocks the agent.
    BlockedBySite,
}

/// The chosen way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    /// Run offer `offer` along `route`.
    Run {
        /// The index of the offer.
        offer: usize,
        /// The route written to the step.
        route: Route,
    },
    /// The step needs the user's session and the user is away: the task waits as `waiting_user` (CP-9).
    WaitForUser {
        /// The index of the offer.
        offer: usize,
        /// The path it will take.
        path: RoutePath,
    },
    /// The user does it.
    Handoff {
        /// Why.
        why: Handoff,
        /// The route written to the step.
        route: Route,
    },
}

const fn rank(path: PathType) -> u8 {
    match path {
        PathType::Api | PathType::Mcp | PathType::CommerceProtocol => 0,
        PathType::OsIntent => 1,
        PathType::Browser => 2,
    }
}

const fn route_path(path: PathType) -> RoutePath {
    match path {
        PathType::Api => RoutePath::Api,
        PathType::Mcp => RoutePath::Mcp,
        PathType::CommerceProtocol => RoutePath::CommerceProtocol,
        PathType::OsIntent => RoutePath::OsIntent,
        PathType::Browser => RoutePath::CloudBrowser,
    }
}

fn usable(offer: Offer, situation: Situation) -> bool {
    offer.working
        && match offer.path {
            PathType::OsIntent => {
                situation.platform == Platform::Android
                    && (!offer.app_function || offer.allowlisted)
            }
            _ => true,
        }
}

fn handoff(why: Handoff) -> Result<Choice, ContractViolation> {
    let text = match why {
        Handoff::NoPath => "cp-12: no path exists or works",
        Handoff::TermsForbidAgents => "cp-14: the site's terms forbid agents",
        Handoff::BlockedBySite => "cp-32: the site blocks the agent",
    };
    Ok(Choice::Handoff {
        why,
        route: Route {
            path: RoutePath::Handoff,
            location: RouteLocation::User,
            reason: RouteReason::parse(text)?,
        },
    })
}

/// Chooses the way for a step from `offers`, given `site` for a browser offer and `situation`.
///
/// # Errors
/// [`ContractViolation`] only if a fixed route reason broke its contract.
pub fn choose(
    offers: &[Offer],
    site: Site,
    situation: Situation,
) -> Result<Choice, ContractViolation> {
    let best = offers
        .iter()
        .enumerate()
        .filter(|(_, o)| usable(**o, situation))
        .min_by_key(|(i, o)| (rank(o.path), *i));
    let Some((index, offer)) = best else {
        return handoff(Handoff::NoPath);
    };
    let path = route_path(offer.path);
    if offer.path == PathType::Browser {
        if site.terms_forbid_agents {
            return handoff(Handoff::TermsForbidAgents);
        }
        if site.blocks_agents {
            return handoff(Handoff::BlockedBySite);
        }
    }
    let local = offer.path == PathType::OsIntent
        || (offer.path == PathType::Browser && situation.needs_session);
    if local && !situation.user_present {
        return Ok(Choice::WaitForUser { offer: index, path });
    }
    let (location, text) = match offer.path {
        PathType::Api | PathType::Mcp | PathType::CommerceProtocol => (
            RouteLocation::CloudExecutor,
            "cp-9: an API, MCP server or commerce protocol runs in the cloud executor",
        ),
        PathType::OsIntent => (
            RouteLocation::LocalExecutor,
            "cp-9: an OS intent runs on the user's device",
        ),
        PathType::Browser if situation.needs_session => (
            RouteLocation::LocalExecutor,
            "cp-9: the user's session is needed and the user is at the device",
        ),
        PathType::Browser => (
            RouteLocation::CloudMicrovm,
            "cp-9: the cloud browser runs in the user's microVM",
        ),
    };
    Ok(Choice::Run {
        offer: index,
        route: Route {
            path,
            location,
            reason: RouteReason::parse(text)?,
        },
    })
}
