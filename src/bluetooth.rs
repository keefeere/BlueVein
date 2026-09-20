use serde::{Deserialize, Serialize};
use std::error::Error;

/// Long Term Key for BLE devices
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeLongTermKey {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc_size: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ediv: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rand: Option<u64>,
}

impl LeLongTermKey {
    /// Missing metadata from another backend is not a request to downgrade the
    /// same key. Never carry security metadata across different key material.
    fn merge_optional(existing: &Option<Self>, preferred: &Option<Self>) -> Option<Self> {
        match (existing, preferred) {
            (Some(a), Some(b)) if a.key.eq_ignore_ascii_case(&b.key) => Some(Self {
                key: b.key.clone(),
                authenticated: b.authenticated.or(a.authenticated),
                enc_size: b.enc_size.or(a.enc_size),
                ediv: b.ediv.or(a.ediv),
                rand: b.rand.or(a.rand),
            }),
            (_, Some(b)) => Some(b.clone()),
            (Some(a), None) => Some(a.clone()),
            (None, None) => None,
        }
    }

    /// Get authenticated value, defaulting to 0 if not set
    pub fn authenticated_or_default(&self) -> u8 {
        self.authenticated.unwrap_or(0)
    }
}

/// Connection Signature Resolving Key with metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CsrkKey {
    pub key: String,
    #[serde(default)]
    pub counter: u32,
    #[serde(default)]
    pub authenticated: bool,
}

impl CsrkKey {
    #[allow(dead_code)]
    pub fn new(key: String) -> Self {
        Self {
            key,
            counter: 0,
            authenticated: false,
        }
    }
}

/// Bluetooth Low Energy specific keys
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LeKeys {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ltk: Option<LeLongTermKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peripheral_ltk: Option<LeLongTermKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub irk: Option<String>,
    /// Explicit shared IRK representation. Legacy records omit this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub irk_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrk_local: Option<CsrkKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrk_remote: Option<CsrkKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_type: Option<String>, // "public" or "random"
}

/// Classic Bluetooth specific keys
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassicKeys {
    pub link_key: String,
    #[serde(default = "default_link_key_type")]
    pub key_type: u8,
    #[serde(default)]
    pub pin_length: u8,
}

fn default_link_key_type() -> u8 {
    4
}

impl ClassicKeys {
    #[allow(dead_code)]
    pub fn new(link_key: String) -> Self {
        Self {
            link_key,
            key_type: 4,
            pin_length: 0,
        }
    }
}

/// Bluetooth device information (supports both Classic and LE)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BluetoothDevice {
    pub mac_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classic: Option<ClassicKeys>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub le: Option<LeKeys>,
}

impl BluetoothDevice {
    /// Create a classic Bluetooth device
    #[allow(dead_code)]
    pub fn classic(mac_address: String, link_key: String) -> Self {
        Self {
            mac_address,
            classic: Some(ClassicKeys::new(link_key)),
            le: None,
        }
    }

    /// Create a BLE device with LTK
    #[allow(dead_code)]
    pub fn le_with_ltk(mac_address: String, ltk: LeLongTermKey) -> Self {
        Self {
            mac_address,
            classic: None,
            le: Some(LeKeys {
                ltk: Some(ltk),
                ..Default::default()
            }),
        }
    }

    /// Check if device has any keys
    pub fn has_keys(&self) -> bool {
        self.classic.is_some() || self.le.as_ref().is_some_and(|le|
            le.ltk.is_some() || le.peripheral_ltk.is_some() || le.irk.is_some()
                || le.csrk_local.is_some() || le.csrk_remote.is_some())
    }

    /// Merge two devices, combining keys from both
    /// Useful for dual-mode devices or when syncing between platforms
    pub fn merge_with(&self, other: &BluetoothDevice) -> BluetoothDevice {
        BluetoothDevice {
            mac_address: self.mac_address.clone(),
            classic: other.classic.clone().or_else(|| self.classic.clone()),
            le: match (&self.le, &other.le) {
                (Some(le1), Some(le2)) => Some(Self::merge_le_keys(le1, le2)),
                (Some(le), None) | (None, Some(le)) => Some(le.clone()),
                (None, None) => None,
            },
        }
    }

    /// Merge LE keys from two sources, preferring non-None values from other
    fn merge_le_keys(le1: &LeKeys, le2: &LeKeys) -> LeKeys {
        LeKeys {
            ltk: LeLongTermKey::merge_optional(&le1.ltk, &le2.ltk),
            peripheral_ltk: LeLongTermKey::merge_optional(&le1.peripheral_ltk, &le2.peripheral_ltk),
            irk: le2.irk.clone().or_else(|| le1.irk.clone()),
            irk_encoding: if le2.irk.is_some() {
                le2.irk_encoding.clone().or_else(|| {
                    if le1.irk == le2.irk { le1.irk_encoding.clone() } else { None }
                })
            } else { le1.irk_encoding.clone() },
            csrk_local: le2.csrk_local.clone().or_else(|| le1.csrk_local.clone()),
            csrk_remote: le2.csrk_remote.clone().or_else(|| le1.csrk_remote.clone()),
            address_type: le2
                .address_type
                .clone()
                .or_else(|| le1.address_type.clone()),
        }
    }
}

/// Validate Bluetooth key length
///
/// Per Bluetooth Core Specification:
/// - LTK, IRK, CSRK: 16 bytes (128 bits) = 32 hex characters
/// - LinkKey (Classic): 16 bytes = 32 hex characters
///
/// # Arguments
/// * `key` - Hex string to validate
/// * `key_name` - Name of the key (for error messages)
///
/// # Returns
/// * `Ok(())` if key is valid
/// * `Err` with descriptive message if invalid
pub fn validate_bluetooth_key(key: &str, key_name: &str) -> Result<(), Box<dyn Error>> {
    const EXPECTED_LENGTH: usize = 32; // 16 bytes = 32 hex chars

    // Check if all characters are valid hex
    if !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{} contains non-hexadecimal characters", key_name).into());
    }

    // Check length
    let actual_length = key.len();
    if actual_length != EXPECTED_LENGTH {
        return Err(format!(
            "{} has invalid length: expected {} hex characters (16 bytes), got {} characters",
            key_name, EXPECTED_LENGTH, actual_length
        )
        .into());
    }

    Ok(())
}

/// Trait for platform-specific Bluetooth management
pub trait BluetoothManager: Send {
    /// Missing OS bonds need platform-specific metadata; do not fabricate them.
    fn import_missing_reason(&self, _device: &BluetoothDevice) -> Option<String> {
        Some("this backend requires an existing OS bond".into())
    }

    /// Explain an unsafe or ambiguous update without blocking unrelated devices.
    fn update_reason(&self, _current: &BluetoothDevice, _desired: &BluetoothDevice) -> Option<String> { None }

    /// Apply an entire import batch once (no-op on registry backends).
    fn apply_pending(&mut self) -> Result<(), Box<dyn Error>> { Ok(()) }

    /// Whether importing the desired record would change fields this backend stores.
    /// Unsupported cross-platform metadata must stay in EFI, not trigger endless writes.
    fn needs_update(&self, current: &BluetoothDevice, desired: &BluetoothDevice) -> bool {
        current != desired
    }

    /// Retain metadata the local backend cannot observe when the key is unchanged.
    fn prepare_local_export(&self, local: &BluetoothDevice, _shared: &BluetoothDevice) -> BluetoothDevice {
        local.clone()
    }

    /// Repair legacy shared-address indexing using verified platform identity metadata.
    fn migrate_shared_config(&self, _config: &mut crate::config::BlueVeinConfig) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Get list of Bluetooth adapter MAC addresses
    fn get_adapters(&self) -> Result<Vec<String>, Box<dyn Error>>;

    /// Get all paired devices for an adapter
    fn get_devices(&self, adapter_mac: &str) -> Result<Vec<BluetoothDevice>, Box<dyn Error>>;

    /// Get specific device information
    fn get_device(
        &self,
        adapter_mac: &str,
        device_mac: &str,
    ) -> Result<BluetoothDevice, Box<dyn Error>>;

    /// Set/update device keys (both classic and LE)
    fn set_device(
        &mut self,
        adapter_mac: &str,
        device: &BluetoothDevice,
    ) -> Result<(), Box<dyn Error>>;

    /// Remove device
    #[allow(dead_code)]
    fn remove_device(&mut self, adapter_mac: &str, device_mac: &str) -> Result<(), Box<dyn Error>>;
}

/// Format MAC address to standard format (XX:XX:XX:XX:XX:XX)
pub fn normalize_mac(mac: &str) -> String {
    let cleaned: String = mac.chars().filter(|c| c.is_alphanumeric()).collect();
    let mut result = String::new();

    for (i, c) in cleaned.chars().enumerate() {
        if i > 0 && i % 2 == 0 {
            result.push(':');
        }
        result.push(c.to_ascii_uppercase());
    }

    result
}

/// Convert MAC address to Windows registry format (XX:XX:XX:XX:XX:XX -> XXXXXXXXXXXX)
#[allow(dead_code)]
pub fn mac_to_windows_format(mac: &str) -> String {
    mac.chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_uppercase()
}

/// Convert Windows registry MAC format to standard (XXXXXXXXXXXX -> XX:XX:XX:XX:XX:XX)
#[allow(dead_code)]
pub fn windows_format_to_mac(win_mac: &str) -> String {
    normalize_mac(win_mac)
}

/// Check if a string is a valid MAC address in raw hex format (12 hex characters, no separators).
/// Used to filter out non-MAC registry values like "CentralIRK", "LocalIRK", etc.
#[allow(dead_code)]
pub fn is_valid_mac_hex(name: &str) -> bool {
    name.len() == 12 && name.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn irk_encoding_tracks_its_key_and_is_not_inherited_after_rekey() {
        let mut local = BluetoothDevice::le_with_ltk("peer".into(), LeLongTermKey { key: "11".repeat(16), authenticated: Some(2), enc_size: Some(16), ediv: Some(0), rand: Some(0) });
        local.le.as_mut().unwrap().irk = Some("22".repeat(16));
        local.le.as_mut().unwrap().irk_encoding = Some("windows".into());
        let mut legacy = local.clone(); legacy.le.as_mut().unwrap().irk_encoding = None;
        assert_eq!(local.merge_with(&legacy).le.unwrap().irk_encoding.as_deref(), Some("windows"));
        legacy.le.as_mut().unwrap().irk = Some("33".repeat(16));
        assert!(local.merge_with(&legacy).le.unwrap().irk_encoding.is_none());
        let json = serde_json::to_string(&local).unwrap();
        assert_eq!(serde_json::from_str::<BluetoothDevice>(&json).unwrap(), local);
    }

    #[test]
    fn same_key_retains_sc_metadata_missing_from_older_exports() {
        let known = LeLongTermKey { key: "AB".repeat(16), authenticated: Some(2), enc_size: Some(16), ediv: Some(0), rand: Some(0) };
        let mut sparse = known.clone(); sparse.key.make_ascii_lowercase(); sparse.authenticated = None;
        assert_eq!(LeLongTermKey::merge_optional(&Some(known.clone()), &Some(sparse.clone())).unwrap().authenticated, Some(2));
        sparse.key = "CD".repeat(16);
        assert_eq!(LeLongTermKey::merge_optional(&Some(known), &Some(sparse)).unwrap().authenticated, None);
    }

    #[test]
    fn test_normalize_mac() {
        assert_eq!(normalize_mac("aabbccddeeff"), "AA:BB:CC:DD:EE:FF");
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF");
        assert_eq!(normalize_mac("AA-BB-CC-DD-EE-FF"), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_mac_conversions() {
        let mac = "AA:BB:CC:DD:EE:FF";
        let win_format = mac_to_windows_format(mac);
        assert_eq!(win_format, "AABBCCDDEEFF");
        assert_eq!(windows_format_to_mac(&win_format), mac);
    }

    #[test]
    fn test_classic_device() {
        let device = BluetoothDevice::classic(
            "AA:BB:CC:DD:EE:FF".to_string(),
            "0123456789ABCDEF".to_string(),
        );
        assert!(device.classic.is_some());
        assert!(device.le.is_none());
        assert!(device.has_keys());

        let classic = device.classic.unwrap();
        assert_eq!(classic.key_type, 4);
        assert_eq!(classic.pin_length, 0);
    }

    #[test]
    fn test_le_device() {
        let ltk = LeLongTermKey {
            key: "0123456789ABCDEF".to_string(),
            authenticated: Some(1),
            enc_size: Some(16),
            ediv: Some(100),
            rand: Some(12345),
        };
        let device = BluetoothDevice::le_with_ltk("AA:BB:CC:DD:EE:FF".to_string(), ltk);
        assert!(device.classic.is_none());
        assert!(device.le.is_some());
        assert!(device.has_keys());
    }

    #[test]
    fn test_ltk_authenticated_default() {
        let ltk = LeLongTermKey {
            key: "0123456789ABCDEF".to_string(),
            authenticated: None,
            enc_size: Some(16),
            ediv: Some(100),
            rand: Some(12345),
        };
        assert_eq!(ltk.authenticated_or_default(), 0);
    }

    #[test]
    fn test_csrk_key_creation() {
        let csrk = CsrkKey::new("0123456789ABCDEF".to_string());
        assert_eq!(csrk.counter, 0);
        assert_eq!(csrk.authenticated, false);
    }

    #[test]
    fn test_merge_devices() {
        let device1 = BluetoothDevice::classic(
            "AA:BB:CC:DD:EE:FF".to_string(),
            "0123456789ABCDEF".to_string(),
        );
        let ltk = LeLongTermKey {
            key: "FEDCBA9876543210".to_string(),
            authenticated: Some(1),
            enc_size: Some(16),
            ediv: Some(100),
            rand: Some(12345),
        };
        let device2 = BluetoothDevice::le_with_ltk("AA:BB:CC:DD:EE:FF".to_string(), ltk);

        let merged = device1.merge_with(&device2);
        assert!(merged.classic.is_some());
        assert!(merged.le.is_some());
    }

    #[test]
    fn test_validate_bluetooth_key_valid() {
        // Valid 32-character hex key
        let key = "0123456789ABCDEF0123456789ABCDEF";
        assert!(validate_bluetooth_key(key, "TestKey").is_ok());
    }

    #[test]
    fn test_validate_bluetooth_key_too_short() {
        let key = "0123456789ABCDEF"; // Only 16 chars (8 bytes)
        let result = validate_bluetooth_key(key, "TestKey");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected 32"));
    }

    #[test]
    fn test_validate_bluetooth_key_too_long() {
        let key = "0123456789ABCDEF0123456789ABCDEF00"; // 34 chars
        let result = validate_bluetooth_key(key, "TestKey");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected 32"));
    }

    #[test]
    fn test_validate_bluetooth_key_invalid_chars() {
        let key = "0123456789ABCDEFGHIJ456789ABCDEF"; // Contains G, H, I, J
        let result = validate_bluetooth_key(key, "TestKey");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-hexadecimal"));
    }

    #[test]
    fn test_validate_bluetooth_key_lowercase() {
        // Lowercase hex should be valid
        let key = "0123456789abcdef0123456789abcdef";
        assert!(validate_bluetooth_key(key, "TestKey").is_ok());
    }

    #[test]
    fn test_is_valid_mac_hex_valid() {
        assert!(is_valid_mac_hex("AABBCCDDEEFF"));
        assert!(is_valid_mac_hex("aabbccddeeff"));
        assert!(is_valid_mac_hex("98038E6A754D"));
    }

    #[test]
    fn test_is_valid_mac_hex_rejects_special_keys() {
        // These are real Windows registry value names that are NOT device MACs
        assert!(!is_valid_mac_hex("CentralIRK"));
        assert!(!is_valid_mac_hex("LocalIRK"));
        assert!(!is_valid_mac_hex("MasterIRK"));
    }

    #[test]
    fn test_is_valid_mac_hex_rejects_wrong_length() {
        assert!(!is_valid_mac_hex("AABBCCDDEE"));     // 10 chars - too short
        assert!(!is_valid_mac_hex("AABBCCDDEEFF00")); // 14 chars - too long
        assert!(!is_valid_mac_hex(""));                // empty
    }

    #[test]
    fn test_is_valid_mac_hex_rejects_non_hex() {
        assert!(!is_valid_mac_hex("AABBCCDDEEGG")); // G is not hex
        assert!(!is_valid_mac_hex("AA:BB:CC:DD:E")); // contains colons
    }
}
