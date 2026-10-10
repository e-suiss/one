//! `one-cli` operates a One deployment: it validates configuration and reports its version, and has no command that reads personal content (SEC-28).

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line tool reports to the terminal"
)]

use std::path::Path;
use std::process::ExitCode;

use one_config::ServerConfig;

fn usage() -> ExitCode {
    eprintln!("usage: one-cli <command>");
    eprintln!("  version              print the version");
    eprintln!("  config check <FILE>  validate a one-server configuration file");
    ExitCode::FAILURE
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
        _ => usage(),
    }
}
