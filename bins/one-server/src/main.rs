//! `one-server` reads and validates its configuration, installs content-free telemetry and serves the public and internal routers; business logic lives in `crates/` (T-4, T-26 (5)).

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use one_config::ServerConfig;
use one_http::{Limits, internal_router, public_router};
use one_telemetry::LeakSink;
use one_telemetry::leak::LeakKind;

#[derive(Default)]
struct SecurityEvents {
    blocked: AtomicU64,
}

impl LeakSink for SecurityEvents {
    fn leak_blocked(&self, _kinds: &[LeakKind]) {
        self.blocked.fetch_add(1, Ordering::Relaxed);
    }
}

fn main() -> ExitCode {
    let path =
        std::env::var_os("ONE_CONFIG").map_or_else(|| PathBuf::from("one.toml"), PathBuf::from);
    let config = match ServerConfig::load(&path) {
        Ok(config) => config,
        Err(error) => {
            #[allow(clippy::print_stderr, reason = "telemetry is not installed yet")]
            {
                eprintln!("one-server: invalid configuration: {error}");
            }
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = one_telemetry::init(&config.log, Arc::new(SecurityEvents::default())) {
        #[allow(clippy::print_stderr, reason = "telemetry failed to install")]
        {
            eprintln!("one-server: {error}");
        }
        return ExitCode::FAILURE;
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(event = "server.runtime_failed", outcome = "error", %error);
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve(&config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(event = "server.stopped", outcome = "error", %error);
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: &ServerConfig) -> std::io::Result<()> {
    let limits = Limits::default();
    let public = tokio::net::TcpListener::bind(config.listen).await?;
    let internal = tokio::net::TcpListener::bind(config.internal_listen).await?;
    let roles: Vec<&str> = config.roles.iter().map(|r| r.as_str()).collect();
    tracing::info!(
        event = "server.listening",
        outcome = "ok",
        listen = %config.listen,
        internal_listen = %config.internal_listen,
        roles = ?roles
    );
    let public = axum::serve(public, public_router(limits)).with_graceful_shutdown(shutdown());
    let internal = axum::serve(internal, internal_router(Vec::new(), limits))
        .with_graceful_shutdown(shutdown());
    let (a, b) = tokio::join!(public.into_future(), internal.into_future());
    a.and(b)
}

async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = terminate.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!(event = "server.shutdown", outcome = "ok");
}
