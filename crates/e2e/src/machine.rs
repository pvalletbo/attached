//! In-container commands. All credentials live in that container's private tmpfs.
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::Path, time::Duration};

use anyhow::{Result, bail, ensure};
use clap::Subcommand;
use tokio::time::Instant;

use crate::{process::strings, random_secret, terminal::Terminal};

const HOME: &str = "/home/attached";

#[derive(Subcommand)]
pub(crate) enum Action {
    Create {
        #[arg(long)]
        service: String,
    },
    Export,
    Serve {
        #[arg(long)]
        proof: String,
    },
    Verify {
        #[arg(long)]
        proof: String,
    },
}

fn password() -> Result<String> {
    let path = Path::new(HOME).join(".test-password");
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut file) => file.write_all(random_secret()?.as_bytes())?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    Ok(std::fs::read_to_string(path)?)
}

async fn command(args: &[&str], create: bool, expected: i32) -> Result<String> {
    let mut argv = vec!["attached".to_owned()];
    argv.extend(strings(args));
    let mut terminal = Terminal::spawn(&argv, password()?, Duration::from_secs(90))?;
    terminal.unlock(create).await?;
    terminal.finish(expected).await
}

fn verify_output(output: &str, proof: &str) -> Result<()> {
    let expected = format!("e2e-publisher\nattached\n{proof}");
    ensure!(
        output == expected,
        "unexpected remote output: {output:?}; expected {expected:?}"
    );
    Ok(())
}

pub(crate) async fn run(action: Action) -> Result<()> {
    match action {
        Action::Create { service } => {
            command(&["account", "create", "--service", &service], true, 0).await?;
            println!("PASS: new account created and saved");
        }
        Action::Export => {
            command(
                &[
                    "account",
                    "export",
                    "--type",
                    "publish",
                    "--output",
                    "/home/attached/publish.bundle",
                ],
                false,
                0,
            )
            .await?;
            println!("PASS: publish-only bundle exported");
        }
        Action::Verify { proof } => {
            let output = command(
                &[
                    "ssh",
                    "--no-cache",
                    "e2e-publisher",
                    "hostname; id -un; cat /home/attached/remote-proof",
                ],
                false,
                0,
            )
            .await?;
            verify_output(&output, &proof)?;
            command(&["ssh", "e2e-publisher", "exit 37"], false, 37).await?;
            println!("PASS: SSH executed on the publisher; output and remote exit status verified");
        }
        Action::Serve { proof } => {
            std::fs::write(Path::new(HOME).join("remote-proof"), format!("{proof}\n"))?;
            let mut terminal = Terminal::spawn(
                &strings(&[
                    "attached",
                    "serve",
                    "--host-label",
                    "e2e-publisher",
                    "--bundle-file",
                    "/home/attached/publish.bundle",
                ]),
                password()?,
                Duration::from_secs(120),
            )?;
            terminal.unlock(true).await?;
            terminal
                .expect("Serving Attached SSH tunnels as `e2e-publisher`.")
                .await?;
            std::fs::remove_file(Path::new(HOME).join("publish.bundle"))?;
            std::fs::write(Path::new(HOME).join("ready"), b"")?;
            println!("PASS: publisher imported the bundle and published its host");
            terminal.deadline = Instant::now() + Duration::from_secs(600);
            terminal.finish(0).await?;
            bail!("publisher stopped before test cleanup");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_proof_requires_correct_host_user_and_fresh_nonce() {
        verify_output("e2e-publisher\nattached\nunique-proof", "unique-proof").unwrap();
        for output in [
            "",
            "e2e-client\nattached\nunique-proof",
            "e2e-publisher\nroot\nunique-proof",
            "e2e-publisher\nattached\nstale",
        ] {
            assert!(verify_output(output, "unique-proof").is_err());
        }
    }
}
