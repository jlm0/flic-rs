//! `flic-cli` — diagnostic + validation harness against a real Flic 2 button.
//!
//! Commands:
//!
//! - `doctor` — reports BLE adapter status
//! - `scan` — discovers Flic 2 peripherals advertising over BLE
//! - `pair <id>` — runs FullVerify against a button in Public Mode
//! - `listen <id> --creds <path>` — reconnects via QuickVerify and prints events

#![allow(clippy::too_many_lines)]

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use flic_core::manager::{FlicEvent, FlicManager};
use flic_core::session::EventResumeState;
use flic_core::PairingCredentials;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::error::RecvError;
use tracing::{error, info};

mod creds;

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
    /// Scans for Flic 2 peripherals. Prints peripheral_id + RSSI + local name.
    Scan {
        #[arg(long, default_value = "8")]
        seconds: u64,
    },
    /// Pairs with a Flic 2 that is in Public Mode. Writes credentials JSON.
    Pair {
        /// Peripheral ID reported by `scan` (platform-specific — a UUID on macOS).
        peripheral_id: String,
        /// Output file for credentials. Defaults to ./creds.json.
        #[arg(long, default_value = "creds.json")]
        out: PathBuf,
    },
    /// Connects using stored credentials and prints events until Ctrl-C.
    Listen {
        peripheral_id: String,
        #[arg(long)]
        creds: PathBuf,
    },
}

/// Serialized form of [`PairingCredentials`] plus event-resume state. The CLI writes
/// this on `pair` and reads it on `listen`.
#[derive(Debug, Serialize, Deserialize)]
struct StoredCreds {
    pairing_id: u32,
    pairing_key_hex: String,
    serial_number: String,
    button_uuid_hex: String,
    firmware_version: u32,
    peripheral_id: String,
    #[serde(default)]
    resume_event_count: u32,
    #[serde(default)]
    resume_boot_id: u32,
}

impl StoredCreds {
    fn from_creds(creds: &PairingCredentials, peripheral_id: &str) -> Self {
        Self {
            pairing_id: creds.pairing_id,
            pairing_key_hex: hex_encode(&creds.pairing_key),
            serial_number: creds.serial_number.clone(),
            button_uuid_hex: hex_encode(&creds.button_uuid),
            firmware_version: creds.firmware_version,
            peripheral_id: peripheral_id.to_string(),
            resume_event_count: 0,
            resume_boot_id: 0,
        }
    }

    fn to_creds(&self) -> anyhow::Result<PairingCredentials> {
        let pairing_key = hex_decode_fixed::<16>(&self.pairing_key_hex)?;
        let button_uuid = hex_decode_fixed::<16>(&self.button_uuid_hex)?;
        Ok(PairingCredentials {
            pairing_id: self.pairing_id,
            pairing_key,
            serial_number: self.serial_number.clone(),
            button_uuid,
            firmware_version: self.firmware_version,
        })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(out, "{b:02x}").expect("write to string");
    }
    out
}

fn hex_decode_fixed<const N: usize>(s: &str) -> anyhow::Result<[u8; N]> {
    if s.len() != N * 2 {
        anyhow::bail!("expected {} hex chars, got {}", N * 2, s.len());
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "flic_cli=debug,flic_core=debug".into()),
        )
        .init();

    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Doctor => doctor().await,
        Command::Scan { seconds } => scan(seconds).await,
        Command::Pair { peripheral_id, out } => pair(&peripheral_id, &out).await,
        Command::Listen {
            peripheral_id,
            creds,
        } => listen(&peripheral_id, &creds).await,
    }
}

async fn doctor() -> anyhow::Result<()> {
    match FlicManager::new().await {
        Ok(_) => {
            info!("BLE adapter available");
            println!("OK: BLE adapter available");
            Ok(())
        }
        Err(e) => {
            error!(%e, "BLE adapter unavailable");
            println!("ERROR: {e}");
            std::process::exit(1);
        }
    }
}

async fn scan(seconds: u64) -> anyhow::Result<()> {
    let manager = FlicManager::new().await?;
    info!(seconds, "scanning for Flic 2 peripherals");
    let found = manager.scan(Duration::from_secs(seconds)).await?;
    if found.is_empty() {
        println!("No Flic 2 peripherals discovered.");
        return Ok(());
    }
    println!("Discovered {} Flic 2 peripheral(s):", found.len());
    for d in &found {
        println!("  id={} rssi={:?} name={:?}", d.id, d.rssi, d.local_name);
    }
    Ok(())
}

/// Keeps calling `manager.find` in short windows, printing a heartbeat every retry,
/// until the target shows up or the user Ctrl-Cs.
async fn find_with_retry(
    manager: &FlicManager,
    peripheral_id: &str,
) -> anyhow::Result<flic_core::Discovery> {
    let per_attempt = Duration::from_secs(8);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match manager.find(peripheral_id, per_attempt).await {
            Ok(target) => return Ok(target),
            Err(e) => {
                info!(attempt, ?e, "no advertisement caught — click the button");
                println!(
                    "  …still waiting (attempt {attempt}). Click the button now; will keep retrying."
                );
            }
        }
    }
}

async fn pair(peripheral_id: &str, out: &std::path::Path) -> anyhow::Result<()> {
    let manager = FlicManager::new().await?;
    println!("Hold the Flic button for ~7 seconds until the LED flashes rapidly and");
    println!("you see two extra flashes AFTER you release it. That's Public Mode —");
    println!("you have ~30 seconds to pair. Starting scan now...");
    info!(id = peripheral_id, "waiting for Public-Mode advertisement");
    let target = manager.find(peripheral_id, Duration::from_secs(30)).await?;
    let creds = manager.pair(&target.id).await?;
    let stored = StoredCreds::from_creds(&creds, peripheral_id);
    let json = serde_json::to_string_pretty(&stored)?;
    std::fs::write(out, json)?;
    println!(
        "Paired. serial={} firmware={} pairing_id={}",
        creds.serial_number, creds.firmware_version, creds.pairing_id
    );
    println!("Credentials written to {}", out.display());
    Ok(())
}

async fn listen(peripheral_id: &str, creds_path: &std::path::Path) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(creds_path)?;
    let stored: StoredCreds = serde_json::from_str(&raw)?;
    let creds = stored.to_creds()?;

    let manager = FlicManager::new().await?;
    println!("Waiting for the Flic button. Click it to wake it — each click fires a");
    println!("brief advertisement that we try to catch. Will retry until you Ctrl-C.");
    let target = find_with_retry(&manager, peripheral_id).await?;

    let mut events = manager.subscribe();

    let resume = EventResumeState {
        event_count: stored.resume_event_count,
        boot_id: stored.resume_boot_id,
    };
    let handle = manager.listen(target.id.clone(), creds, resume).await?;

    info!("listening for events; press Ctrl-C to quit");

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                println!("Disconnecting...");
                handle.disconnect().await;
                break;
            }
            result = events.recv() => {
                match result {
                    Ok(event) => print_event(&event),
                    Err(RecvError::Closed) => {
                        println!("Event channel closed.");
                        break;
                    }
                    Err(RecvError::Lagged(n)) => {
                        eprintln!("WARNING: lagged {n} events");
                    }
                }
            }
        }
    }
    Ok(())
}

fn print_event(event: &FlicEvent) {
    match event {
        FlicEvent::Connected {
            id,
            battery_voltage_mv,
            firmware_version,
        } => {
            println!(
                "[{}] Connected — battery={battery_voltage_mv}mV fw={firmware_version}",
                short_id(&format!("{id}"))
            );
        }
        FlicEvent::EventsResumed {
            id,
            event_count,
            boot_id,
            has_queued_events,
        } => {
            println!(
                "[{}] EventsResumed — count={event_count} boot_id={boot_id} queued={has_queued_events}",
                short_id(&format!("{id}"))
            );
        }
        FlicEvent::ButtonPressed {
            id,
            kind,
            timestamp_32k,
            was_queued,
        } => {
            println!(
                "[{}] {kind:?} ts={timestamp_32k}{}",
                short_id(&format!("{id}")),
                if *was_queued { " (queued)" } else { "" }
            );
        }
        FlicEvent::Disconnected { id, reason } => {
            println!("[{}] Disconnected: {reason:?}", short_id(&format!("{id}")));
        }
        FlicEvent::Reconnecting {
            id,
            attempt,
            after,
            last_reason,
        } => {
            println!(
                "[{}] Reconnecting in {:.1}s (attempt {attempt}) after {last_reason:?}",
                short_id(&format!("{id}")),
                after.as_secs_f32()
            );
        }
        FlicEvent::AdapterUnavailable { id } => {
            println!(
                "[{}] Adapter unavailable — waiting for Bluetooth",
                short_id(&format!("{id}"))
            );
        }
    }
}

fn short_id(id: &str) -> String {
    // macOS peripheral IDs look like UUIDs; show the first 8 chars for readability.
    id.chars().take(8).collect()
}
