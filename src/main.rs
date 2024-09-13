mod repeater;
mod cli;
mod structs;
mod helper;

use clap::Parser;
use env_logger::{Builder, Env};
use repeater::create_poll;
use std::sync::Arc;
use cli::Args;

use helper::exit_with_err;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    Builder::from_env(Env::default().default_filter_or("info"))
        .format_target(false)
        .init();

    let args = Args::parse();
    let settings = Arc::new(
        args.move_to_setting()
            .unwrap_or_else(|err| exit_with_err(err)),
    );

    tokio::select! {
        result = create_poll(Arc::clone(&settings)) => {
            if let Err(err) = result {
                exit_with_err(err)
            }
        },
        _ = tokio::signal::ctrl_c() => {
            log::warn!("Shutdown");
        }
    }

    println!();
}
