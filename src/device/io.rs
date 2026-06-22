//! Tauri Commands to interact with the pico-fido firmware via rescue and fido protocols.
#![allow(unused)]

use crate::{device::fido, device::rescue, device::types::*, error::PFError};

pub fn read_device_details() -> Result<FullDeviceStatus, PFError> {
    match rescue::read_device_details() {
        Ok(status) => Ok(status),
        Err(e) => {
            log::warn!("Rescue method failed: {}. Falling back to FIDO...", e);
            fido::read_device_details()
        }
    }
}

pub fn write_config(
    config: AppConfigInput,
    method: DeviceMethod,
    pin: Option<String>,
) -> Result<String, PFError> {
    if method == DeviceMethod::Fido {
        fido::write_config(config, pin)
    } else {
        rescue::write_config(config)
    }
}

pub fn enable_secure_boot(lock: bool) -> Result<String, PFError> {
    rescue::enable_secure_boot(lock)
}

pub(crate) fn get_fido_info() -> Result<FidoDeviceInfo, String> {
    fido::get_fido_info()
}

pub(crate) fn change_fido_pin(
    current_pin: Option<String>,
    new_pin: String,
) -> Result<String, String> {
    fido::change_fido_pin(current_pin, new_pin)
}

pub(crate) fn set_min_pin_length(
    current_pin: String,
    min_pin_length: u8,
) -> Result<String, String> {
    fido::set_min_pin_length(current_pin, min_pin_length)
}

pub fn reboot(to_bootsel: bool) -> Result<String, PFError> {
    rescue::reboot_device(to_bootsel)
}

pub fn get_credentials(pin: String) -> Result<Vec<StoredCredential>, String> {
    fido::get_credentials(pin)
}

pub fn delete_credential(pin: String, credential_id: String) -> Result<String, String> {
    fido::delete_credential(pin, credential_id)
}

pub fn reset_device() -> Result<String, String> {
    fido::reset_device()
}

pub fn read_led_config() -> Result<LedStatusConfig, PFError> {
    rescue::read_led_config()
}

pub fn write_led_status(status: u8, color: u8, brightness: u8, steady: bool) -> Result<String, PFError> {
    rescue::write_led_status(status, color, brightness, steady)
}

pub fn read_management_config() -> Result<ManagementAppConfig, PFError> {
    rescue::read_management_config()
}

pub fn write_management_config(enabled_mask: u16) -> Result<String, PFError> {
    rescue::write_management_config(enabled_mask)
}

pub fn enable_enterprise_attestation(pin: String) -> Result<String, String> {
    fido::enable_enterprise_attestation(pin)
}

pub fn get_enterprise_attestation_csr() -> Result<String, String> {
    fido::get_enterprise_attestation_csr()
}

pub fn upload_enterprise_attestation_cert(
    pin: String,
    cert_path: String,
) -> Result<String, String> {
    fido::upload_enterprise_attestation_cert(pin, cert_path)
}
