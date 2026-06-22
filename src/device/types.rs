#![allow(unused)]

use serde::{Deserialize, Serialize};
use std::fmt;

struct PForgeState {
    device_info: DeviceInfo,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub serial: String,
    pub flash_used: Option<u32>,
    pub flash_total: Option<u32>,
    pub firmware_version: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub vid: String,
    pub pid: String,
    pub product_name: String,
    pub led_gpio: u8,
    pub led_brightness: u8,
    pub touch_timeout: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub led_driver: Option<u8>,
    pub led_dimmable: bool,
    pub power_cycle_on_reset: bool,
    pub led_steady: bool,
    pub enable_secp256k1: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_curves_mask: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub led_order: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled_usb_itf: Option<u8>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppConfigInput {
    pub vid: Option<String>,
    pub pid: Option<String>,
    pub product_name: Option<String>,
    pub led_gpio: Option<u8>,
    pub led_brightness: Option<u8>,
    pub touch_timeout: Option<u8>,
    pub led_driver: Option<u8>,
    pub led_dimmable: Option<bool>,
    pub power_cycle_on_reset: Option<bool>,
    pub led_steady: Option<bool>,
    pub enable_secp256k1: Option<bool>,
    pub raw_curves_mask: Option<u32>,
    pub led_order: Option<u8>,
    pub enabled_usb_itf: Option<u8>,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FullDeviceStatus {
    pub info: DeviceInfo,
    pub config: AppConfig,
    pub secure_boot: bool,
    pub secure_lock: bool,
    pub method: DeviceMethod,
    pub firmware_type: FirmwareType,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DeviceMethod {
    #[serde(rename = "FIDO")]
    Fido,
    Rescue,
}

/// Represents the recognized firmware variants running on the connected hardware token.
/// Used extensively to gate UI features, connection methods, and compatibility checks.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub enum FirmwareType {
    PicoFido,
    RSKey,
    #[default]
    Unknown,
}

impl fmt::Display for FirmwareType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PicoFido => write!(f, "Pico-FIDO"),
            Self::RSKey => write!(f, "RS-Key"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// The globally unique Authenticator Attestation GUID (AAGUID) assigned to RS-Key hardware.
pub const RSKEY_AAGUID: &str = "2479C7BF6B3056839EC80E8171A918B7";
/// The globally unique Authenticator Attestation GUID (AAGUID) assigned to Pico-Fido hardware.
pub const PICOFIDO_AAGUID: &str = "89FB94B706C936739B7E30526D968145";

/// Aggregates the LED status configurations read from the RS-Key Vendor/LED applet.
/// Contains the global steady flag and a fixed array of `(color_code, brightness)` pairs
/// mapped chronologically to device statuses: [Idle, Processing, Touch, Boot].
#[derive(Serialize, Debug, Default, Clone, PartialEq)]
pub struct LedStatusConfig {
    pub steady: bool,
    pub statuses: [(u8, u8); 4],
}

/// Encapsulates the bitmasks defining USB application endpoints on the device.
/// The `usb_supported` mask indicates which applets the firmware is capable of running,
/// while `usb_enabled` reflects the active endpoints the device will enumerate on next boot.
#[derive(Serialize, Debug, Default, Clone, PartialEq)]
pub struct ManagementAppConfig {
    pub usb_supported: u16,
    pub usb_enabled: u16,
}

// Fido stuff:

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FidoDeviceInfo {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: String,
    pub options: std::collections::HashMap<String, bool>,
    pub max_msg_size: i128,
    pub pin_protocols: Vec<u32>,
    pub remaining_discoverable_credentials: Option<i128>,
    pub min_pin_length: i128,
    pub firmware_version: String,
    /// Supported vendor config commands (human-readable names), parsed from CTAP GetInfo.
    pub vendor_config_commands: Vec<String>,
    /// Device certifications when firmware exposes them separately from vendor commands.
    pub certifications: std::collections::HashMap<String, bool>,
    pub max_credential_count_in_list: Option<i128>,
    pub max_credential_id_length: Option<i128>,
    pub algorithms: Vec<String>,
    pub max_serialized_large_blob_array: Option<i128>,
    pub force_pin_change: Option<bool>,
    pub max_cred_blob_length: Option<i128>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredCredential {
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_id: String,
    pub credential_id: String,
}
