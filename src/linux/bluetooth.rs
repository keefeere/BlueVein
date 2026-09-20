use crate::bluetooth::{
    normalize_mac, validate_bluetooth_key, BluetoothDevice, BluetoothManager, ClassicKeys, CsrkKey,
    LeKeys, LeLongTermKey,
};
use crate::log;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const BLUETOOTH_LIB_PATH: &str = "/var/lib/bluetooth";

// Explicit compatibility override for existing Windows-format shared records.
// Use the same involution on import and export; never change the shared key.
fn translate_irk(key: &str, adapter: &str, peer: &str, peers: &str) -> Result<String, Box<dyn Error>> {
    let selected = format!("{}/{}", normalize_mac(adapter), normalize_mac(peer));
    let mut reverse = false;
    for entry in peers.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (a, p) = entry.split_once('/').ok_or("Invalid Linux IRK override; expected adapter/peer")?;
        for mac in [a, p] {
            if mac.len() != 17 || mac.split(':').count() != 6 ||
                !mac.split(':').all(|b| b.len() == 2 && b.bytes().all(|c| c.is_ascii_hexdigit())) {
                return Err("Invalid MAC in Linux IRK override".into());
            }
        }
        reverse |= entry.eq_ignore_ascii_case(&selected);
    }
    if !reverse { return Ok(key.to_string()); }
    validate_bluetooth_key(key, "IRK")?;
    let mut bytes = hex::decode(key).map_err(|_| "Invalid IRK encoding")?;
    bytes.reverse();
    Ok(hex::encode_upper(bytes))
}

fn configured_irk(key: &str, adapter: &str, peer: &str) -> Result<String, Box<dyn Error>> {
    let peers = std::env::var("BLUEVEIN_LINUX_REVERSE_IRK_PEERS").unwrap_or_default();
    translate_irk(key, adapter, peer, &peers)
}

#[cfg(test)]
mod irk_encoding_tests {
    use super::translate_irk;
    const A: &str = "44:F7:9F:AC:CD:9C";
    const P: &str = "10:A2:D3:01:47:A1";
    const KEY: &str = "000102030405060708090A0B0C0D0E0F";
    #[test]
    fn scoped_conversion_round_trips_shared_windows_record() {
        let selected = format!("{A}/{P}");
        let linux = translate_irk(KEY, A, P, &selected).unwrap();
        assert_eq!(linux, "0F0E0D0C0B0A09080706050403020100");
        assert_eq!(translate_irk(&linux, A, P, &selected).unwrap(), KEY);
        assert_eq!(translate_irk(KEY, A, "10:A2:D3:01:47:A2", &selected).unwrap(), KEY);
        assert_eq!(translate_irk(KEY, "44:F7:9F:AC:CD:9D", P, &selected).unwrap(), KEY);
        assert_eq!(translate_irk(KEY, A, P, "").unwrap(), KEY);
    }
    #[test]
    fn invalid_override_is_rejected_even_for_unselected_peer() {
        assert!(translate_irk(KEY, A, P, "invalid").is_err());
        assert!(translate_irk(KEY, A, P, "00:00:00:00:00:ZZ/10:A2:D3:01:47:A1").is_err());
    }
}

pub struct LinuxBluetoothManager;

impl LinuxBluetoothManager {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        // Reject malformed configuration before any synchronization starts.
        configured_irk("00000000000000000000000000000000", "00:00:00:00:00:00", "00:00:00:00:00:00")?;
        Ok(Self)
    }

    fn get_adapter_info_path(adapter_mac: &str) -> PathBuf {
        PathBuf::from(BLUETOOTH_LIB_PATH).join(normalize_mac(adapter_mac))
    }

    fn get_device_info_path(adapter_mac: &str, device_mac: &str) -> PathBuf {
        Self::get_adapter_info_path(adapter_mac)
            .join(normalize_mac(device_mac))
            .join("info")
    }

    /// Parse the info file and extract all keys (Classic and LE)
    fn read_device_keys(
        adapter_mac: &str,
        device_mac: &str,
    ) -> Result<BluetoothDevice, Box<dyn Error>> {
        let info_path = Self::get_device_info_path(adapter_mac, device_mac);
        let content = fs::read_to_string(&info_path)
            .map_err(|e| format!("Failed to read {}: {}", info_path.display(), e))?;

        // Parse INI-like format into sections
        let sections = Self::parse_info_file(&content);

        let mut device = BluetoothDevice {
            mac_address: normalize_mac(device_mac),
            classic: None,
            le: None,
        };

        // Parse Classic LinkKey
        if let Some(link_key_section) = sections.get("LinkKey") {
            if let Some(key) = link_key_section.get("Key") {
                // Validate LinkKey length
                if let Err(e) = validate_bluetooth_key(key, "LinkKey") {
                    log!(
                        "[BlueVein] Warning: Invalid LinkKey for device {}: {}",
                        device_mac,
                        e
                    );
                } else {
                    let key_type = link_key_section
                        .get("Type")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(4);
                    let pin_length = link_key_section
                        .get("PINLength")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);

                    device.classic = Some(ClassicKeys {
                        link_key: key.clone(),
                        key_type,
                        pin_length,
                    });
                }
            }
        }

        // Parse LE keys
        let mut le_keys = LeKeys::default();
        let mut has_le = false;

        // Parse LongTermKey (Central)
        if let Some(ltk_section) = sections.get("LongTermKey") {
            if let Some(key) = ltk_section.get("Key") {
                // Validate LTK length
                if let Err(e) = validate_bluetooth_key(key, "LTK") {
                    log!(
                        "[BlueVein] Warning: Invalid LTK for device {}: {}",
                        device_mac,
                        e
                    );
                } else {
                    le_keys.ltk = Some(LeLongTermKey {
                        key: key.clone(),
                        authenticated: ltk_section
                            .get("Authenticated")
                            .and_then(|v| v.parse().ok()),
                        enc_size: ltk_section.get("EncSize").and_then(|v| v.parse().ok()),
                        ediv: ltk_section.get("EDiv").and_then(|v| v.parse().ok()),
                        rand: ltk_section.get("Rand").and_then(|v| v.parse().ok()),
                    });
                    has_le = true;
                }
            }
        }

        // Parse PeripheralLongTermKey
        if let Some(pltk_section) = sections.get("PeripheralLongTermKey") {
            if let Some(key) = pltk_section.get("Key") {
                // Validate Peripheral LTK length
                if let Err(e) = validate_bluetooth_key(key, "PeripheralLTK") {
                    log!(
                        "[BlueVein] Warning: Invalid PeripheralLTK for device {}: {}",
                        device_mac,
                        e
                    );
                } else {
                    le_keys.peripheral_ltk = Some(LeLongTermKey {
                        key: key.clone(),
                        authenticated: pltk_section
                            .get("Authenticated")
                            .and_then(|v| v.parse().ok()),
                        enc_size: pltk_section.get("EncSize").and_then(|v| v.parse().ok()),
                        ediv: pltk_section.get("EDiv").and_then(|v| v.parse().ok()),
                        rand: pltk_section.get("Rand").and_then(|v| v.parse().ok()),
                    });
                    has_le = true;
                }
            }
        }

        // Parse IdentityResolvingKey
        if let Some(irk_section) = sections.get("IdentityResolvingKey") {
            if let Some(key) = irk_section.get("Key") {
                // Validate IRK length
                if let Err(e) = validate_bluetooth_key(key, "IRK") {
                    log!(
                        "[BlueVein] Warning: Invalid IRK for device {}: {}",
                        device_mac,
                        e
                    );
                } else {
                    le_keys.irk = Some(configured_irk(key, adapter_mac, device_mac)?);
                    has_le = true;
                }
            }
        }

        // Parse LocalSignatureKey
        if let Some(lsk_section) = sections.get("LocalSignatureKey") {
            if let Some(key) = lsk_section.get("Key") {
                // Validate CSRK length
                if let Err(e) = validate_bluetooth_key(key, "CSRK (Local)") {
                    log!(
                        "[BlueVein] Warning: Invalid LocalSignatureKey for device {}: {}",
                        device_mac,
                        e
                    );
                } else {
                    let counter = lsk_section
                        .get("Counter")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let authenticated = lsk_section
                        .get("Authenticated")
                        .map(|v| v.to_lowercase() == "true")
                        .unwrap_or(false);

                    le_keys.csrk_local = Some(CsrkKey {
                        key: key.clone(),
                        counter,
                        authenticated,
                    });
                    has_le = true;
                }
            }
        }

        // Parse RemoteSignatureKey (CSRK)
        if let Some(rsk_section) = sections.get("RemoteSignatureKey") {
            if let Some(key) = rsk_section.get("Key") {
                // Validate CSRK length
                if let Err(e) = validate_bluetooth_key(key, "CSRK (Remote)") {
                    log!(
                        "[BlueVein] Warning: Invalid RemoteSignatureKey for device {}: {}",
                        device_mac,
                        e
                    );
                } else {
                    let counter = rsk_section
                        .get("Counter")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let authenticated = rsk_section
                        .get("Authenticated")
                        .map(|v| v.to_lowercase() == "true")
                        .unwrap_or(false);

                    le_keys.csrk_remote = Some(CsrkKey {
                        key: key.clone(),
                        counter,
                        authenticated,
                    });
                    has_le = true;
                }
            }
        }

        // Parse AddressType from [General] section
        if let Some(general_section) = sections.get("General") {
            if let Some(addr_type) = general_section.get("AddressType") {
                le_keys.address_type = Some(addr_type.clone());
                has_le = true;
            }
        }

        if has_le {
            device.le = Some(le_keys);
        }

        if !device.has_keys() {
            return Err(format!("No keys found for device {}", device_mac).into());
        }

        Ok(device)
    }

    /// Parse INI-like info file into sections
    fn parse_info_file(content: &str) -> HashMap<String, HashMap<String, String>> {
        let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut current_section = String::new();

        for line in content.lines() {
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Section header
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                current_section = trimmed[1..trimmed.len() - 1].to_string();
                sections
                    .entry(current_section.clone())
                    .or_insert_with(HashMap::new);
                continue;
            }

            // Key=Value pair
            if let Some(pos) = trimmed.find('=') {
                let key = trimmed[..pos].trim().to_string();
                let value = trimmed[pos + 1..].trim().to_string();

                if !current_section.is_empty() {
                    sections
                        .entry(current_section.clone())
                        .or_insert_with(HashMap::new)
                        .insert(key, value);
                }
            }
        }

        sections
    }

    /// Write device info to file (both Classic and LE keys)
    fn write_device_keys(
        adapter_mac: &str,
        device: &BluetoothDevice,
    ) -> Result<(), Box<dyn Error>> {
        let device_dir =
            Self::get_adapter_info_path(adapter_mac).join(normalize_mac(&device.mac_address));
        let info_path = device_dir.join("info");

        // Ensure device directory exists
        fs::create_dir_all(&device_dir)?;

        // Read existing file if it exists
        let existing_sections = if info_path.exists() {
            let content = fs::read_to_string(&info_path)?;
            Self::parse_info_file(&content)
        } else {
            HashMap::new()
        };

        // Build new sections map
        let mut sections = existing_sections;

        // Update Classic LinkKey
        if let Some(classic) = &device.classic {
            // Validate before writing
            validate_bluetooth_key(&classic.link_key, "LinkKey")?;

            let link_key_section = sections
                .entry("LinkKey".to_string())
                .or_insert_with(HashMap::new);
            link_key_section.insert("Key".to_string(), classic.link_key.clone());
            link_key_section.insert("Type".to_string(), classic.key_type.to_string());
            link_key_section.insert("PINLength".to_string(), classic.pin_length.to_string());
        }

        // Update LE keys
        if let Some(le) = &device.le {
            // LongTermKey (Central)
            if let Some(ltk) = &le.ltk {
                // Validate before writing
                validate_bluetooth_key(&ltk.key, "LTK")?;

                let ltk_section = sections
                    .entry("LongTermKey".to_string())
                    .or_insert_with(HashMap::new);
                ltk_section.insert("Key".to_string(), ltk.key.clone());
                // Use authenticated_or_default() to ensure we write 0 if not set
                ltk_section.insert(
                    "Authenticated".to_string(),
                    ltk.authenticated_or_default().to_string(),
                );
                if let Some(enc_size) = ltk.enc_size {
                    ltk_section.insert("EncSize".to_string(), enc_size.to_string());
                }
                if let Some(ediv) = ltk.ediv {
                    ltk_section.insert("EDiv".to_string(), ediv.to_string());
                }
                if let Some(rand) = ltk.rand {
                    ltk_section.insert("Rand".to_string(), rand.to_string());
                }
            }

            // PeripheralLongTermKey
            if let Some(pltk) = &le.peripheral_ltk {
                // Validate before writing
                validate_bluetooth_key(&pltk.key, "PeripheralLTK")?;

                let pltk_section = sections
                    .entry("PeripheralLongTermKey".to_string())
                    .or_insert_with(HashMap::new);
                pltk_section.insert("Key".to_string(), pltk.key.clone());
                pltk_section.insert(
                    "Authenticated".to_string(),
                    pltk.authenticated_or_default().to_string(),
                );
                if let Some(enc_size) = pltk.enc_size {
                    pltk_section.insert("EncSize".to_string(), enc_size.to_string());
                }
                if let Some(ediv) = pltk.ediv {
                    pltk_section.insert("EDiv".to_string(), ediv.to_string());
                }
                if let Some(rand) = pltk.rand {
                    pltk_section.insert("Rand".to_string(), rand.to_string());
                }
            }

            // IdentityResolvingKey
            if let Some(irk) = &le.irk {
                // Validate before writing
                validate_bluetooth_key(irk, "IRK")?;

                let irk_section = sections
                    .entry("IdentityResolvingKey".to_string())
                    .or_insert_with(HashMap::new);
                irk_section.insert("Key".to_string(), configured_irk(irk, adapter_mac, &device.mac_address)?);
            }

            // LocalSignatureKey
            if let Some(csrk_local) = &le.csrk_local {
                // Validate before writing
                validate_bluetooth_key(&csrk_local.key, "CSRK (Local)")?;

                let lsk_section = sections
                    .entry("LocalSignatureKey".to_string())
                    .or_insert_with(HashMap::new);
                lsk_section.insert("Key".to_string(), csrk_local.key.clone());
                lsk_section.insert("Counter".to_string(), csrk_local.counter.to_string());
                lsk_section.insert(
                    "Authenticated".to_string(),
                    csrk_local.authenticated.to_string(),
                );
            }

            // RemoteSignatureKey
            if let Some(csrk_remote) = &le.csrk_remote {
                // Validate before writing
                validate_bluetooth_key(&csrk_remote.key, "CSRK (Remote)")?;

                let rsk_section = sections
                    .entry("RemoteSignatureKey".to_string())
                    .or_insert_with(HashMap::new);
                rsk_section.insert("Key".to_string(), csrk_remote.key.clone());
                rsk_section.insert("Counter".to_string(), csrk_remote.counter.to_string());
                rsk_section.insert(
                    "Authenticated".to_string(),
                    csrk_remote.authenticated.to_string(),
                );
            }

            // AddressType in [General] section
            if let Some(address_type) = &le.address_type {
                let general_section = sections
                    .entry("General".to_string())
                    .or_insert_with(HashMap::new);
                general_section.insert("AddressType".to_string(), address_type.clone());
            }
        }

        // Serialize sections back to file
        let mut content = String::new();
        for (section_name, section_data) in sections {
            content.push_str(&format!("[{}]\n", section_name));
            for (key, value) in section_data {
                content.push_str(&format!("{}={}\n", key, value));
            }
            content.push('\n');
        }

        fs::write(&info_path, content)?;

        // Restart bluetooth service to apply changes
        Self::restart_bluetooth_service();

        Ok(())
    }

    fn restart_bluetooth_service() {
        // Try to restart bluetooth service (ignore errors)
        let _ = Command::new("systemctl")
            .args(["restart", "bluetooth"])
            .output();
    }
}

impl BluetoothManager for LinuxBluetoothManager {
    fn get_adapters(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let mut adapters = Vec::new();

        if !PathBuf::from(BLUETOOTH_LIB_PATH).exists() {
            return Ok(adapters);
        }

        for entry in fs::read_dir(BLUETOOTH_LIB_PATH)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();

            // Check if it looks like a MAC address
            if name.contains(':') && name.len() == 17 && entry.file_type()?.is_dir() {
                adapters.push(normalize_mac(&name));
            }
        }

        Ok(adapters)
    }

    fn get_devices(&self, adapter_mac: &str) -> Result<Vec<BluetoothDevice>, Box<dyn Error>> {
        let adapter_path = Self::get_adapter_info_path(adapter_mac);
        let mut devices = Vec::new();

        if !adapter_path.exists() {
            return Ok(devices);
        }

        for entry in fs::read_dir(&adapter_path)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }

            let device_mac = entry.file_name().to_string_lossy().to_string();

            // Check if it looks like a MAC address
            if device_mac.contains(':') && device_mac.len() == 17 {
                if let Ok(device) = Self::read_device_keys(adapter_mac, &device_mac) {
                    devices.push(device);
                }
            }
        }

        Ok(devices)
    }

    fn get_device(
        &self,
        adapter_mac: &str,
        device_mac: &str,
    ) -> Result<BluetoothDevice, Box<dyn Error>> {
        Self::read_device_keys(adapter_mac, device_mac)
    }

    fn set_device(
        &mut self,
        adapter_mac: &str,
        device: &BluetoothDevice,
    ) -> Result<(), Box<dyn Error>> {
        Self::write_device_keys(adapter_mac, device)
    }

    fn remove_device(&mut self, adapter_mac: &str, device_mac: &str) -> Result<(), Box<dyn Error>> {
        let device_path = Self::get_adapter_info_path(adapter_mac).join(normalize_mac(device_mac));

        if device_path.exists() {
            fs::remove_dir_all(&device_path)
                .map_err(|e| format!("Failed to remove device directory: {}", e))?;
        }

        Ok(())
    }
}
