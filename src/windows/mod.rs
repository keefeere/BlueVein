mod bluetooth;
mod monitor;
mod service;

use crate::efi::EfiContext;
use crate::log;
use crate::sync::SyncManager;
use std::error::Error;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub fn run() -> Result<(), Box<dyn Error>> {
    // Check if running as service or standalone
    if std::env::args().any(|arg| arg == "--service") {
        service::run_service()
    } else {
        // Parse command line arguments
        let args: Vec<String> = std::env::args().collect();

        if args.len() > 1 {
            match args[1].as_str() {
                "install" => service::install_service(),
                "uninstall" => service::uninstall_service(),
                "start" => service::start_service(),
                "stop" => service::stop_service(),
                _ => {
                    log!("BlueVein - Bluetooth Synchronization Service");
                    log!("\nUsage:");
                    log!("  bluevein.exe install   - Install service");
                    log!("  bluevein.exe uninstall - Uninstall service");
                    log!("  bluevein.exe start     - Start service");
                    log!("  bluevein.exe stop      - Stop service");
                    Ok(())
                }
            }
        } else {
            // Run standalone (for testing)
            log!("[BlueVein] Running in standalone mode...");
            run_sync_loop()
        }
    }
}

pub fn run_sync_loop() -> Result<(), Box<dyn Error>> {
    let bt_manager = Box::new(bluetooth::WindowsBluetoothManager::new()?);

    let efi_context = EfiContext::from_env();
    efi_context.validate()?;

    let mut sync_manager = SyncManager::new(bt_manager, efi_context);

    log!("[BlueVein] Performing initial bidirectional sync...");
    if let Err(e) = sync_manager.sync_bidirectional() {
        log!("[BlueVein] Warning: Initial sync failed: {}", e);
        log!("[BlueVein] Continuing with monitoring...");
    }

    let running = Arc::new(AtomicBool::new(true));

    // Set up Ctrl+C handler for standalone mode
    let running_clone = running.clone();
    ctrlc::set_handler(move || {
        log!("\n[BlueVein] Shutting down...");
        running_clone.store(false, Ordering::Relaxed);
    })
    .ok();

    // Start monitoring with registry change notifications
    log!("[BlueVein] Starting registry monitoring...");
    monitor::monitor_bluetooth_changes(sync_manager, running)
}
