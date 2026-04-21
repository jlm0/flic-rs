//! `flic-cli` — diagnostic and validation harness. Exercises `flic-core` against a real
//! Flic 2 button without Electron, napi, or any other runtime in the loop.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "flic-cli")]
#[command(about = "Diagnostic harness for the flic-core Flic 2 implementation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Reports BLE adapter state. Exits non-zero on any issue.
    Doctor,
    /// Stub — scaffold only, transport not yet implemented.
    Scan,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "flic_cli=info,flic_core=info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Doctor => {
            println!("flic-cli doctor: transport layer not yet implemented");
            Ok(())
        }
        Command::Scan => {
            println!("flic-cli scan: transport layer not yet implemented");
            Ok(())
        }
    }
}
