use clap::Parser;
use csrf_killer::repeater::create_poll;
use csrf_killer::util::{cli::Args, helper::exit_with_err};
use env_logger::{Builder, Env};
use std::sync::Arc;
use std::time::Duration;

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
            tokio::time::sleep(Duration::from_millis(5)).await;
            log::warn!("Shutdown");
        }
    }
}
