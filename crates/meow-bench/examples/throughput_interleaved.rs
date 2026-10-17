//! Compare two or three already-running SOCKS proxies using the normal throughput
//! workloads. Keeping them warm and rotating order reduces startup/load bias.

#[path = "../src/bench_throughput.rs"]
mod bench_throughput;
#[path = "../src/echo_server.rs"]
mod echo_server;
// The shared client also contains domain helpers unused by these IP workloads.
#[allow(dead_code)]
#[path = "../src/socks5_client.rs"]
mod socks5_client;

use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser)]
struct Args {
    /// SOCKS addresses in result-variant order (e.g. meow and mihomo).
    #[arg(required = true, num_args = 2..=3)]
    proxies: Vec<SocketAddr>,

    /// Rounds per proxy; multiples of six balance every ordering equally.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u32).range(1..))]
    rounds: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let (echo, server) = echo_server::start_echo_server().await?;
    let orders: &[&[usize]] = if args.proxies.len() == 2 {
        &[&[0, 1], &[1, 0]]
    } else {
        &[
            &[0, 1, 2],
            &[0, 2, 1],
            &[1, 0, 2],
            &[1, 2, 0],
            &[2, 0, 1],
            &[2, 1, 0],
        ]
    };

    // Exercise the same path before recording any variant's samples.
    for &proxy in &args.proxies {
        bench_throughput::bench_throughput(proxy, echo).await?;
    }

    let mut samples = Vec::new();
    for round in 0..args.rounds {
        for &variant in orders[round as usize % orders.len()] {
            let throughput =
                bench_throughput::bench_throughput(args.proxies[variant], echo).await?;
            samples.push(serde_json::json!({
                "round": round,
                "variant": variant,
                "throughput": throughput,
            }));
        }
        eprintln!("completed round {}/{}, all proxies", round + 1, args.rounds);
    }
    server.abort();
    println!("{}", serde_json::to_string_pretty(&samples)?);
    Ok(())
}
