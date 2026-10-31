//! `one-cli` operates a One deployment: it validates configuration, runs the separate schema migration step and reports its version, and has no command that reads personal content (SEC-28, OP-27).

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line tool reports to the terminal"
)]

use std::path::Path;
use std::process::ExitCode;

use one_config::ServerConfig;
use one_store::connect::{self, Durability, Target};

fn usage() -> ExitCode {
    eprintln!("usage: one-cli <command>");
    eprintln!("  version              print the version");
    eprintln!("  config check <FILE>  validate a one-server configuration file");
    eprintln!("  db migrate           apply the schema migrations as the migration role");
    eprintln!("    ONE_DB_HOST ONE_DB_PORT ONE_DB_NAME ONE_DB_USER ONE_DB_PASSWORD_FILE");
    eprintln!("    ONE_DB_ROOT_CERT_FILE ONE_DB_DURABILITY=replicated|single-node");
    ExitCode::FAILURE
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

fn read(name: &str) -> Result<Vec<u8>, String> {
    let path = env(name)?;
    std::fs::read(&path).map_err(|e| format!("{name}={path}: {e}"))
}

async fn migrate() -> Result<(), String> {
    let host = env("ONE_DB_HOST")?;
    let port = env("ONE_DB_PORT")?
        .parse()
        .map_err(|e| format!("ONE_DB_PORT: {e}"))?;
    let database = env("ONE_DB_NAME")?;
    let user = env("ONE_DB_USER")?;
    let password = String::from_utf8(read("ONE_DB_PASSWORD_FILE")?)
        .map_err(|_| "ONE_DB_PASSWORD_FILE is not UTF-8".to_owned())?;
    let root_cert = read("ONE_DB_ROOT_CERT_FILE")?;
    let durability = match env("ONE_DB_DURABILITY")?.as_str() {
        "replicated" => Durability::Replicated,
        "single-node" => Durability::SingleNode,
        other => {
            return Err(format!(
                "ONE_DB_DURABILITY={other}: replicated or single-node"
            ));
        }
    };
    let options = connect::options(&Target {
        host: &host,
        port,
        database: &database,
        user: &user,
        password: password.trim_end(),
        root_cert: &root_cert,
    });
    let pool = connect::pool(options, 1).await.map_err(|e| e.to_string())?;
    connect::check_server(&pool, 1, true, durability)
        .await
        .map_err(|e| e.to_string())?;
    one_store::migrate(&pool).await.map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["version"] => {
            println!("one-cli {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["config", "check", file] => {
            let path = Path::new(file);
            if !path.is_file() {
                eprintln!("{file}: not a file");
                return ExitCode::FAILURE;
            }
            match ServerConfig::load(path) {
                Ok(config) => {
                    let roles: Vec<&str> = config.roles.iter().map(|r| r.as_str()).collect();
                    println!(
                        "ok  listen={} internal_listen={} roles={}",
                        config.listen,
                        config.internal_listen,
                        roles.join(",")
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("invalid: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        ["db", "migrate"] => {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("runtime: {error}");
                    return ExitCode::FAILURE;
                }
            };
            match runtime.block_on(migrate()) {
                Ok(()) => {
                    println!("ok  migrations applied");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("migrate: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => usage(),
    }
}
