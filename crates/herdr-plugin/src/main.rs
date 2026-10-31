mod app;
mod attached;
mod core;
mod discovery;
mod herdr;
mod lifecycle;
mod process;
mod state;

use std::time::Duration;

use anyhow::{Context, Result, bail};

const PLUGIN_ID: &str = "attached.discovery";
const INTERVAL: Duration = Duration::from_secs(30);

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Attached Herdr plugin: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [action] if action == "install" => {
            let (device, inode) = lifecycle::identity(&std::env::current_exe()?)?;
            lifecycle::launch(&[
                "__install-wait".into(),
                device.to_string(),
                inode.to_string(),
            ])
        }
        [action] if action == "ensure" => {
            std::env::var_os("HERDR_PLUGIN_STATE_DIR")
                .context("ensure must be invoked by a Herdr hook/action")?;
            lifecycle::launch(&["run".into()])
        }
        [action] if action == "run" => {
            // No controlling terminal: even programs using /dev/tty cannot prompt.
            rustix::process::setsid().context("could not detach discovery worker")?;
            runtime()?.block_on(lifecycle::worker())
        }
        [action, device, inode] if action == "__install-wait" => {
            rustix::process::setsid().context("could not detach install waiter")?;
            let expected = (device.parse()?, inode.parse()?);
            runtime()?.block_on(lifecycle::await_registration(
                &herdr::Herdr::default(),
                expected,
                Duration::from_secs(120),
            ));
            Ok(())
        }
        [action, home] if action == "app-install" => app::install(std::path::Path::new(home)),
        [action, directory] if action == "app-heartbeat" || action == "app-pause" => {
            app::heartbeat(
                std::path::Path::new(directory),
                action == "app-heartbeat",
                false,
            )
        }
        [action, directory, flag] if action == "app-heartbeat" && flag == "--install-core" => {
            app::heartbeat(std::path::Path::new(directory), true, true)
        }
        [action, directory] if action == "app-run" => {
            rustix::process::setsid().context("could not detach app discovery worker")?;
            runtime()?.block_on(app::worker(std::path::Path::new(directory)))
        }
        _ => bail!(
            "usage: attached-herdr-plugin install|ensure (legacy Herdr)\n  app-install <absolute-app-home>\n  app-heartbeat <absolute-state-directory> [--install-core]\n  app-pause <absolute-state-directory>"
        ),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
