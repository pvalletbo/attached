//! Docker-based account -> publishing -> SSH E2E. No application test doubles.
mod backend;
mod docker;
mod machine;
mod process;
mod release;
mod smoke;
mod terminal;
#[cfg(test)]
mod workflow_tests;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    about = "Test account creation, publish bundles, and SSH in disposable Docker machines",
    after_help = "Run: cargo run --locked -p attached-e2e -- [--release 0.3.5]\n\nBy default, build the real Worker and run it locally with Wrangler/workerd.\nBackend accounts, credentials, and runtime state live in disposable tmpfs.\nNo Cloudflare login is needed. --archive tests a candidate .tar.xz with its\nadjacent .sha256 rather than rebuilding/downloading a published version.\n\n--service https://herdr.attached.sh explicitly opts into PRODUCTION instead.\nExternal runs leave one backend account because there is no deletion API.\n\nClient and publisher use separate networks and loopback-only forwarders. No\nhost credentials, ports, or Docker socket are mounted. Failures and Ctrl-C/\nSIGTERM trigger cleanup; hard kills may require removing resources with the\nprinted io.attached.e2e-run label. This is not fully offline: builds/downloads\nand Iroh discovery/relays still require internet access."
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
    #[command(name = "__backend-config", hide = true)]
    BackendConfig { path: std::path::PathBuf },
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
        Some(Internal::BackendConfig { path }) => backend::print_config(&path),
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
            ""
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
        assert!(
            Cli::try_parse_from([
                "attached-e2e",
                "--release",
                "0.3.5",
                "--archive",
                "candidate.tar.xz"
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from(["attached-e2e", "--archive", "candidate.tar.xz"]).unwrap();
        assert_eq!(
            cli.options.archive.unwrap(),
            std::path::PathBuf::from("candidate.tar.xz")
        );
    }
}
