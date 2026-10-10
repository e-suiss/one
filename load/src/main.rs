//! `one-load --addr HOST:PORT --path /livez --rate N --seconds S` sends GET requests at a fixed rate whether or not earlier ones finished, and prints latency percentiles measured from each request's scheduled time as JSON (F-21).

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line tool reports to the terminal"
)]
#![allow(clippy::disallowed_methods, reason = "T-27")]

use std::process::ExitCode;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, MissedTickBehavior};

struct Args {
    addr: String,
    path: String,
    rate: u32,
    seconds: u32,
}

fn parse() -> Option<Args> {
    let mut args = Args {
        addr: String::new(),
        path: "/livez".to_owned(),
        rate: 0,
        seconds: 0,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next()?;
        match flag.as_str() {
            "--addr" => args.addr = value,
            "--path" => args.path = value,
            "--rate" => args.rate = value.parse().ok()?,
            "--seconds" => args.seconds = value.parse().ok()?,
            _ => return None,
        }
    }
    (!args.addr.is_empty() && args.rate > 0 && args.seconds > 0 && args.path.starts_with('/'))
        .then_some(args)
}

enum Outcome {
    Ok(Duration),
    Failed,
}

async fn one(addr: String, request: String, scheduled: Instant) -> Outcome {
    let attempt = async {
        let mut stream = TcpStream::connect(&addr).await?;
        stream.write_all(request.as_bytes()).await?;
        let mut head = [0_u8; 12];
        stream.read_exact(&mut head).await?;
        Ok::<_, std::io::Error>(head.starts_with(b"HTTP/1.1 2"))
    };
    match tokio::time::timeout(Duration::from_secs(10), attempt).await {
        Ok(Ok(true)) => Outcome::Ok(scheduled.elapsed()),
        _ => Outcome::Failed,
    }
}

fn percentile(sorted: &[Duration], p: usize) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let last = sorted.len().saturating_sub(1);
    let at = last.saturating_mul(p) / 100;
    sorted.get(at).map_or(0, Duration::as_micros)
}

#[tokio::main]
async fn main() -> ExitCode {
    let Some(args) = parse() else {
        eprintln!("usage: one-load --addr HOST:PORT [--path /livez] --rate N --seconds S");
        return ExitCode::FAILURE;
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        args.path, args.addr
    );
    let total = args.rate.saturating_mul(args.seconds);
    let mut ticker = tokio::time::interval(
        Duration::from_secs(1)
            .checked_div(args.rate)
            .unwrap_or(Duration::from_secs(1)),
    );
    ticker.set_missed_tick_behavior(MissedTickBehavior::Burst);
    let mut tasks = Vec::new();
    for _ in 0..total {
        let scheduled = ticker.tick().await;
        tasks.push(tokio::spawn(one(
            args.addr.clone(),
            request.clone(),
            scheduled,
        )));
    }
    let mut latencies = Vec::with_capacity(tasks.len());
    let mut failed = 0_u64;
    for task in tasks {
        match task.await {
            Ok(Outcome::Ok(d)) => latencies.push(d),
            _ => failed = failed.saturating_add(1),
        }
    }
    latencies.sort_unstable();
    println!(
        "{{\"sent\":{total},\"ok\":{},\"failed\":{failed},\"rate\":{},\"p50_us\":{},\"p90_us\":{},\"p99_us\":{},\"max_us\":{}}}",
        latencies.len(),
        args.rate,
        percentile(&latencies, 50),
        percentile(&latencies, 90),
        percentile(&latencies, 99),
        latencies.last().map_or(0, Duration::as_micros)
    );
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
