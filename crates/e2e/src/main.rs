//! Docker-based account -> publishing -> SSH E2E. No application test doubles.
mod docker;
mod machine;
mod process;
mod release;
mod smoke;
mod terminal;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    about = "Test account creation, publish bundles, and SSH in disposable Docker machines",
    after_help = "Run: cargo run --locked -p attached-e2e -- [--release 0.3.5]\n\nThe default backend is PRODUCTION. Each run creates one account; the backend\nhas no deletion API, so its state remains. --service selects another origin.\nClient and publisher have separate networks and tmpfs credentials. No host\ncredentials, SSH configuration, ports or Docker socket are mounted. Secrets\nare not logged or retained. Ctrl-C/SIGTERM and failures trigger cleanup. Hard\nkills may require removing resources with the printed io.attached.e2e-run label.\nInternet access is needed for builds, the backend, and Iroh discovery/relays."
)]
struct Cli {
    #[command(flatten)]
    options: smoke::Options,
    #[command(subcommand)]
    internal: Option<Internal>,
}

#[derive(Subcommand)]
enum Internal {
    #[command(name = "__machine", hide = true)]
    Machine {
        #[command(subcommand)]
        action: machine::Action,
    },
    #[command(name = "__install-release", hide = true)]
    InstallRelease {
        #[arg(value_parser = release::validate_version)]
        version: String,
    },
}

fn random_secret() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

async fn interrupted() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("could not register SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = terminate.recv() => {},
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.internal {
        Some(Internal::Machine { action }) => machine::run(action).await,
        Some(Internal::InstallRelease { version }) => release::install(&version).await,
        None => {
            smoke::Smoke::new(docker::Docker, cli.options)?
                .run_until(interrupted())
                .await
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("FAIL: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_and_release_override_parse_without_contacting_backend() {
        assert_eq!(
            Cli::try_parse_from(["attached-e2e"])
                .unwrap()
                .options
                .service,
            smoke::PRODUCTION
        );
        let cli = Cli::try_parse_from([
            "attached-e2e",
            "--release",
            "0.3.5",
            "--service",
            "https://test.example",
        ])
        .unwrap();
        assert_eq!(cli.options.release.as_deref(), Some("0.3.5"));
        assert_eq!(cli.options.service, "https://test.example");
        assert!(Cli::try_parse_from(["attached-e2e", "--release", "latest"]).is_err());
    }
}
