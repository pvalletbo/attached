use std::process::ExitCode;

use clap::Parser;

mod account_clipboard;
mod attached_version;
mod bounded_process;
mod cli;
mod config;
mod diagnostics;
mod download_account;
mod endpoint_registry;
mod herdr_version;
mod identity;
mod installation;
mod local_encryption;
mod local_sockets;
mod proxy;
mod publish_account;
mod secure_state;
mod serve_handoff;
mod server;
mod session;
mod session_picker;
mod sync;
mod tunnel;

#[cfg(test)]
mod test_support;

use cli::Cli;

fn main() -> ExitCode {
    if account_clipboard::helper_requested() {
        return match account_clipboard::serve() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("Error: {error:#}");
                ExitCode::FAILURE
            }
        };
    }
    async_main()
}

#[tokio::main]
async fn async_main() -> ExitCode {
    let cli = Cli::parse();
    let verbosity = cli.verbosity();
    let diagnostics_guard = match diagnostics::init(verbosity, cli.flamegraph()) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("Error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = cli.run().await;
    drop(diagnostics_guard);
    match result {
        Ok(code) => exit_code(code),
        Err(error) => {
            eprintln!("Error: {}", diagnostics::format_error(&error, verbosity));
            ExitCode::FAILURE
        }
    }
}

fn exit_code(code: i32) -> ExitCode {
    u8::try_from(code)
        .map(ExitCode::from)
        .unwrap_or(ExitCode::FAILURE)
}
