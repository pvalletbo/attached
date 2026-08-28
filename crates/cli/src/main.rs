use std::process::ExitCode;

use clap::Parser;

mod bounded_process;
mod cli;
mod diagnostics;
mod endpoint_registry;
mod herdr_version;
mod identity;
mod installation;
mod local_encryption;
mod local_sockets;
mod proxy;
mod secure_state;
mod server;
mod session;
mod session_picker;
mod sync;
mod tunnel;

#[cfg(test)]
mod test_support;

use cli::Cli;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let verbosity = cli.verbosity();
    if let Err(error) = diagnostics::init(verbosity) {
        eprintln!("Error: {error}");
        return ExitCode::FAILURE;
    }
    match cli.run().await {
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
