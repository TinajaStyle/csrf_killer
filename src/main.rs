mod cli;
mod helper;
mod requester;
mod structs;

use clap::Parser;
use cli::Args;
use env_logger::{Builder, Env};
use helper::{art, exit_with_err};
use requester::create_workers;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() {
    Builder::from_env(Env::default().default_filter_or("info"))
        .format_target(false)
        .init();

    let args = Args::parse();

    art();

    let settings = Arc::new(
        args.move_to_setting()
            .unwrap_or_else(|err| exit_with_err(err)),
    );

    tokio::select! {
        result = create_workers(Arc::clone(&settings)) => {
            if let Err(err) = result {
                exit_with_err(err)
            }
        },
        _ = tokio::signal::ctrl_c() => {
            log::warn!("Shutdown");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
