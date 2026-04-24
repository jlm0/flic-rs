//! `flic-cli` — diagnostic + validation harness against a real Flic 2 button.
//!
//! Commands:
//!
//! - `doctor` — reports BLE adapter status
//! - `scan` — discovers Flic 2 peripherals advertising over BLE
//! - `pair <id>` — runs FullVerify against a button in Public Mode
//! - `listen <id> --creds <path>` — reconnects via QuickVerify and prints events,
//!   with automatic reconnect + persisted event continuity

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use flic_core::manager::{FlicEvent, FlicManager};
use flic_core::{AdapterState, EventResumeState, ReconnectPolicy};
use tokio::sync::broadcast::error::RecvError;
use tracing::{error, info};

mod creds;

use creds::StoredCreds;

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
    /// Connects using stored credentials, auto-reconnects on drops, and prints
    /// events until Ctrl-C. Event continuity is persisted back to the creds file.
    Listen {
        peripheral_id: String,
        #[arg(long)]
        creds: PathBuf,
    },
    /// Forgets a pairing on our side: deletes the credentials file. The button
    /// still holds our pairing_id in its internal table until it reboots and
    /// queries `TestIfReallyUnpaired`, or until it's factory-reset physically.
    Forget {
        #[arg(long)]
        creds: PathBuf,
        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
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
        Command::Forget { creds, yes } => forget(&creds, yes),
    }
}

async fn doctor() -> anyhow::Result<()> {
    let manager = FlicManager::new()
        .await
        .map_err(|e| anyhow::anyhow!("BLE adapter unavailable: {e}"))?;
    let state = manager.adapter_state().await;
    if state == AdapterState::PoweredOn {
        info!("BLE adapter powered on");
        println!("OK: BLE adapter powered on");
        Ok(())
    } else {
        anyhow::bail!("BLE adapter not powered on (state: {state:?})")
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

fn forget(creds_path: &Path, skip_confirm: bool) -> anyhow::Result<()> {
    let stored = creds::read(creds_path)?;

    println!("About to forget this pairing:");
    println!("  serial        {}", stored.serial_number);
    println!("  pairing_id    {}", stored.pairing_id);
    println!("  peripheral_id {}", stored.peripheral_id);
    println!("  file          {}", creds_path.display());
    println!();
    println!(
        "The Flic 2 protocol has no host-initiated unpair. The button keeps our"
    );
    println!(
        "pairing_id in its internal table until it reboots (battery swap) or is"
    );
    println!("factory-reset. Until then it will still advertise on clicks.");

    if !skip_confirm {
        use std::io::{self, Write};
        print!("Proceed? [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !matches!(input.trim(), "y" | "Y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    std::fs::remove_file(creds_path)?;
    info!(path = %creds_path.display(), "credentials deleted");
    println!("Forgotten. {} removed.", creds_path.display());
    Ok(())
}

async fn pair(peripheral_id: &str, out: &Path) -> anyhow::Result<()> {
    let manager = FlicManager::new().await?;
    // Flic 2 has no LED, beep, or haptic — no on-button feedback to rely on.
    // Instructions here intentionally reference only observable behavior
    // (time the hold, watch the CLI).
    println!("Hold the Flic button for ~7 seconds — count by the clock; there is no");
    println!("LED or beep. When you release, the button enters Public Mode for ~30");
    println!("seconds and this command will report once it's picked up over BLE.");
    info!(id = peripheral_id, "waiting for Public-Mode advertisement");
    let target = manager.find(peripheral_id, Duration::from_secs(30)).await?;
    let pairing = manager.pair(&target.id).await?;
    let stored = StoredCreds::from_pairing(&pairing, peripheral_id);
    creds::write_atomic(&stored, out)?;
    println!(
        "Paired. serial={} firmware={} pairing_id={}",
        pairing.serial_number, pairing.firmware_version, pairing.pairing_id
    );
    println!("Credentials written to {}", out.display());
    Ok(())
}

async fn listen(peripheral_id: &str, creds_path: &Path) -> anyhow::Result<()> {
    let stored = creds::read(creds_path)?;
    let pairing = stored.to_pairing()?;
    let initial_resume = stored.resume_state();

    let manager = FlicManager::new().await?;
    println!("Waiting for the Flic button. Click it to wake it — each click fires a");
    println!("brief advertisement that we try to catch. Will keep reconnecting");
    println!("automatically; press Ctrl-C to stop.");

    let target = manager.find(peripheral_id, Duration::from_secs(3600)).await?;
    let mut events = manager.subscribe();

    let handle = manager
        .listen_with_reconnect(
            target.id.clone(),
            pairing,
            initial_resume,
            ReconnectPolicy::default(),
        )
        .await?;

    let resume_rx = handle.subscribe_resume();
    let drainer = spawn_drainer(resume_rx, creds_path.to_path_buf(), stored);

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

    drainer.shutdown().await;
    Ok(())
}

/// Background task that persists the latest `EventResumeState` back to the
/// creds file. Coalesces updates to at most one write per
/// `PERSISTENCE_INTERVAL` (10s) and guarantees a final flush on shutdown.
const PERSISTENCE_INTERVAL: Duration = Duration::from_secs(10);

struct DrainerHandle {
    task: tokio::task::JoinHandle<()>,
    shutdown_tx: tokio::sync::mpsc::Sender<()>,
}

impl DrainerHandle {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(()).await;
        let _ = self.task.await;
    }
}

fn spawn_drainer(
    mut resume_rx: tokio::sync::watch::Receiver<EventResumeState>,
    creds_path: PathBuf,
    mut stored: StoredCreds,
) -> DrainerHandle {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    let task = tokio::spawn(async move {
        let mut last_written = stored.resume_state();
        let mut ticker = tokio::time::interval(PERSISTENCE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // drain the immediate first tick

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    flush_resume(*resume_rx.borrow(), last_written, &mut stored, &creds_path);
                    return;
                }
                _ = ticker.tick() => {
                    let latest = *resume_rx.borrow();
                    if flush_resume(latest, last_written, &mut stored, &creds_path) {
                        last_written = latest;
                        info!(
                            event_count = latest.event_count,
                            boot_id = latest.boot_id,
                            "creds file updated"
                        );
                    }
                }
                change = resume_rx.changed() => {
                    // Writes are owned by the ticker (intentional 10s debounce).
                    // This arm exists only to observe sender-drop — when the
                    // supervisor exits the channel closes, and we must final-
                    // flush before returning or the last few events are lost.
                    if change.is_err() {
                        flush_resume(*resume_rx.borrow(), last_written, &mut stored, &creds_path);
                        return;
                    }
                }
            }
        }
    });
    DrainerHandle { task, shutdown_tx }
}

/// Writes `latest` to disk if it differs from `last_written`. Returns `true`
/// when a write succeeded so the caller can advance `last_written`; returns
/// `false` on no-op or write failure (error is logged).
fn flush_resume(
    latest: EventResumeState,
    last_written: EventResumeState,
    stored: &mut StoredCreds,
    path: &Path,
) -> bool {
    if latest.event_count == last_written.event_count && latest.boot_id == last_written.boot_id {
        return false;
    }
    stored.update_resume(latest);
    match creds::write_atomic(stored, path) {
        Ok(()) => true,
        Err(e) => {
            error!(?e, "creds write failed");
            false
        }
    }
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
                short_id(id)
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
                short_id(id)
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
                short_id(id),
                if *was_queued { " (queued)" } else { "" }
            );
        }
        FlicEvent::Disconnected { id, reason } => {
            println!("[{}] Disconnected: {reason:?}", short_id(id));
        }
        FlicEvent::Reconnecting {
            id,
            attempt,
            after_millis,
            last_reason,
        } => {
            println!(
                "[{}] Reconnecting in {:.1}s (attempt {attempt}) after {last_reason:?}",
                short_id(id),
                *after_millis as f32 / 1000.0
            );
        }
        FlicEvent::AdapterUnavailable { id } => {
            println!(
                "[{}] Adapter unavailable — waiting for Bluetooth",
                short_id(id)
            );
        }
    }
}

fn short_id(id: &str) -> String {
    // macOS peripheral IDs look like UUIDs; show the first 8 chars for readability.
    id.chars().take(8).collect()
}
