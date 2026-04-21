//! `flic-cli` — diagnostic + validation harness against a real Flic 2 button.
//!
//! Commands:
//!
//! - `doctor` — reports BLE adapter status
//! - `scan` — discovers Flic 2 peripherals advertising over BLE
//! - `pair <id>` — runs FullVerify against a button in Public Mode
//! - `listen <id> --creds <path>` — reconnects via QuickVerify and prints events,
//!   with automatic reconnect + persisted event continuity

#![allow(clippy::too_many_lines)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use flic_core::manager::{FlicEvent, FlicManager};
use flic_core::{CentralState, ReconnectPolicy};
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
        Command::Forget { creds, yes } => forget(&creds, yes).await,
    }
}

async fn doctor() -> anyhow::Result<()> {
    let manager = match FlicManager::new().await {
        Ok(m) => m,
        Err(e) => {
            error!(%e, "BLE adapter unavailable");
            println!("ERROR: {e}");
            std::process::exit(1);
        }
    };
    let state = manager.adapter_state().await;
    if state == CentralState::PoweredOn {
        info!("BLE adapter powered on");
        println!("OK: BLE adapter powered on");
        Ok(())
    } else {
        error!(?state, "BLE adapter not powered on");
        println!("ERROR: BLE adapter not powered on (state: {state:?})");
        std::process::exit(1);
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

async fn forget(creds_path: &Path, skip_confirm: bool) -> anyhow::Result<()> {
    let stored = match creds::read(creds_path) {
        Ok(s) => s,
        Err(e) => {
            println!("ERROR: cannot read {}: {e}", creds_path.display());
            std::process::exit(1);
        }
    };

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
    println!("Hold the Flic button for ~7 seconds until the LED flashes rapidly and");
    println!("you see two extra flashes AFTER you release it. That's Public Mode —");
    println!("you have ~30 seconds to pair. Starting scan now...");
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

    // Final flush of resume state before exit.
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
    mut resume_rx: tokio::sync::watch::Receiver<flic_core::EventResumeState>,
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
                    // Final flush.
                    let latest = *resume_rx.borrow();
                    if latest.event_count != last_written.event_count
                        || latest.boot_id != last_written.boot_id
                    {
                        stored.update_resume(latest);
                        if let Err(e) = creds::write_atomic(&stored, &creds_path) {
                            error!(?e, "final creds write failed");
                        }
                    }
                    return;
                }
                _ = ticker.tick() => {
                    let latest = *resume_rx.borrow();
                    if latest.event_count == last_written.event_count
                        && latest.boot_id == last_written.boot_id
                    {
                        continue;
                    }
                    stored.update_resume(latest);
                    match creds::write_atomic(&stored, &creds_path) {
                        Ok(()) => {
                            last_written = latest;
                            info!(
                                event_count = latest.event_count,
                                boot_id = latest.boot_id,
                                "creds file updated"
                            );
                        }
                        Err(e) => {
                            error!(?e, "creds write failed — will retry on next tick");
                        }
                    }
                }
                change = resume_rx.changed() => {
                    if change.is_err() {
                        // Sender dropped — supervisor has exited. Final flush and exit.
                        let latest = *resume_rx.borrow();
                        if latest.event_count != last_written.event_count
                            || latest.boot_id != last_written.boot_id
                        {
                            stored.update_resume(latest);
                            if let Err(e) = creds::write_atomic(&stored, &creds_path) {
                                error!(?e, "final creds write failed");
                            }
                        }
                        return;
                    }
                    // Value advanced. Writes are owned by the ticker (intentional
                    // 10s debounce). This arm only exists to detect sender-drop
                    // above — we mark the change as seen and let the ticker do
                    // the persistence.
                }
            }
        }
    });
    DrainerHandle { task, shutdown_tx }
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
            after,
            last_reason,
        } => {
            println!(
                "[{}] Reconnecting in {:.1}s (attempt {attempt}) after {last_reason:?}",
                short_id(id),
                after.as_secs_f32()
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
