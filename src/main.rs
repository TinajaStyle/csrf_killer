mod repeater;
mod cli;
mod structs;
mod helper;

use clap::Parser;
use env_logger::{Builder, Env};
use repeater::create_poll;
use std::sync::Arc;
use cli::Args;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    Builder::from_env(Env::default().default_filter_or("info"))
        .format_target(false)
        .init();

    let args = Args::parse();
    let settings = Arc::new(args.move_to_setting());

    create_poll(Arc::clone(&settings)).await;

    println!();
}
