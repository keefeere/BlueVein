mod bluetooth;
mod monitor;

use crate::efi::EfiContext;
use crate::log;
use crate::sync::SyncManager;
use std::error::Error;

pub fn run() -> Result<(), Box<dyn Error>> {
    log!("[BlueVein] Starting Linux service...");

    // Check if we have root permissions
    if !nix::unistd::Uid::effective().is_root() {
        log!("[BlueVein] ERROR: Must run as root!");
        log!("[BlueVein] Please run with: sudo ./bluevein");
        return Err("Requires root privileges".into());
    }

    // Create tokio runtime and run async code
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(run_service())
}

async fn run_service() -> Result<(), Box<dyn Error>> {
    let bt_manager = Box::new(bluetooth::LinuxBluetoothManager::new()?);

    let efi_context = EfiContext::from_env();
    efi_context.validate()?;

    let mut sync_manager = SyncManager::new(bt_manager, efi_context);

    log!("[BlueVein] Performing initial bidirectional sync...");
    // Use bidirectional sync to properly merge EFI and system state
    sync_manager.sync_bidirectional()?;

    // Start monitoring Bluetooth changes
    log!("[BlueVein] Starting Bluetooth monitoring...");
    monitor::monitor_bluetooth_changes(sync_manager).await
}
