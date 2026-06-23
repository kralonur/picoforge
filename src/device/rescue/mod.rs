//! Implements communication with the pico-fido firmware via the `Rescue API`.
//!
//! For more details checkout the [pico-key-sdk](https://github.com/polhenarejos/pico-keys-sdk/blob/main/src/rescue.c)

pub mod constants;

use crate::device::{rescue::constants::*, types::*};
use crate::error::PFError;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use pcsc::{Context, Protocols, Scope, ShareMode};
use std::io::Cursor;

/// Connects to the first available reader and selects the Rescue Applet
fn connect_and_select() -> Result<(pcsc::Card, Vec<u8>, FirmwareType), PFError> {
    let ctx = Context::establish(Scope::User).map_err(|e| {
        log::error!("Failed to establish PCSC context: {}", e);
        PFError::Pcsc(e)
    })?;

    let mut readers_buf = [0; 2048];
    let mut readers = ctx.list_readers(&mut readers_buf)?;

    // Use the first reader found
    let reader = readers.next().ok_or_else(|| {
        log::info!("No Smart Card Reader found");
        PFError::NoDevice
    })?;

    let reader_name = reader.to_string_lossy();
    let mut fw_type = if reader_name.contains("RS-Key") || reader_name.contains("RSK") {
        FirmwareType::RSKey
    } else {
        FirmwareType::Unknown
    };

    let card = ctx.connect(reader, ShareMode::Shared, Protocols::ANY)?;

    // Select Applet APDU: 00 A4 04 04 [Len] [AID]
    let mut apdu = vec![
        APDU_CLA_ISO,
        APDU_INS_SELECT,
        APDU_P1_SELECT_BY_DF_NAME,
        APDU_P2_RETURN_FCI,
        RESCUE_AID.len() as u8,
    ];
    apdu.extend_from_slice(RESCUE_AID);

    let mut rx_buf = [0; 256];
    let rx = card.transmit(&apdu, &mut rx_buf)?;

    // Check Success (0x90 0x00)
    if !rx.ends_with(&[0x90, 0x00]) {
        log::error!("Rescue Applet not found on the device!");
        return Err(PFError::Device(
            // There is no such mode as fido, i tink the rescue applet stays active and at the same time fido mode works?
            // Need to study this more.
            "Rescue Applet not found on device. Is it in FIDO mode?".into(),
        ));
    }

    let data = rx.to_vec();

    if fw_type == FirmwareType::Unknown {
        if data.len() >= 4 && data[2] >= 8 {
            fw_type = FirmwareType::RSKey;
        } else {
            fw_type = FirmwareType::PicoFido;
        }
    }

    log::info!("Successfully connected to Rescue Applet");
    log::info!("Detected firmware type: {:?}", fw_type);
    Ok((card, data, fw_type))
}

pub fn read_device_details() -> Result<FullDeviceStatus, PFError> {
    log::info!("Reading full device details");
    let (card, select_resp, fw_type) = connect_and_select()?;

    log::info!("Select Response: {:?}", select_resp);

    // FIX: Relax the length check.
    // Minimum valid response is 4 bytes data + 2 bytes SW = 6 bytes.
    if select_resp.len() < 6 {
        log::error!("Invalid select response length: {}", select_resp.len());
        return Err(PFError::Device("Invalid select response".into()));
    }

    let version_major = select_resp[2];
    let version_minor = select_resp[3];

    // FIX: Handle missing Serial Number safely
    // If the firmware sends 14 bytes, we have a serial. If it sends 6, we don't.
    let serial_str = if select_resp.len() >= 14 {
        hex::encode_upper(&select_resp[4..12])
    } else {
        log::warn!(
            "Device did not return a Serial Number (Firmware mismatch?). Using placeholder."
        );
        "00000000".to_string()
    };

    log::info!("Device Version: {}.{}", version_major, version_minor);
    log::info!("Device Serial: {}", serial_str);

    // 2. Read Flash Info
    let mut rx_buf = [0; 256];
    let rx_flash = card.transmit(
        &[
            APDU_CLA_PROPRIETARY,
            RescueInstruction::Read as u8,
            ReadParam::FlashInfo as u8,
            P2_UNUSED,
            0x00, // Le
        ],
        &mut rx_buf,
    )?;

    if !rx_flash.ends_with(&SW_SUCCESS) {
        return Err(PFError::Device("Failed to read flash".into()));
    }

    let mut rdr = Cursor::new(&rx_flash[..rx_flash.len() - 2]);
    let _free = rdr.read_u32::<BigEndian>().unwrap_or(0);
    let used = rdr.read_u32::<BigEndian>().unwrap_or(0);
    let total = rdr.read_u32::<BigEndian>().unwrap_or(0);

    // NOTE: captured but currently unused variables
    let _nfiles = rdr.read_u32::<BigEndian>().unwrap_or(0);
    let _chip_size = rdr.read_u32::<BigEndian>().unwrap_or(0);

    // --- Read Secure Boot Status ---
    let rx_secure = card.transmit(
        &[
            APDU_CLA_PROPRIETARY,
            RescueInstruction::Read as u8,
            ReadParam::SecureBootStatus as u8,
            P2_UNUSED,
            0x00,
        ],
        &mut rx_buf,
    )?;

    let (sb_enabled, sb_locked) = if rx_secure.ends_with(&[0x90, 0x00]) && rx_secure.len() >= 4 {
        (rx_secure[0] != 0, rx_secure[1] != 0)
    } else {
        (false, false)
    }; // --- Read PHY Config ---
    let rx_phy = card.transmit(
        &[
            APDU_CLA_PROPRIETARY,
            RescueInstruction::Read as u8,
            ReadParam::PhyConfig as u8,
            0x01,
            0x00,
        ],
        &mut rx_buf,
    )?;

    if !rx_phy.ends_with(&[0x90, 0x00]) {
        return Err(PFError::Device("Failed to read config".into()));
    }

    // Parse TLV
    let mut config = AppConfig::default();
    let data = &rx_phy[..rx_phy.len() - 2];
    let mut i = 0;
    while i < data.len() {
        if i + 2 > data.len() {
            break;
        }
        let tag_byte = data[i];
        let len = data[i + 1] as usize;
        i += 2;
        if i + len > data.len() {
            break;
        }
        let val = &data[i..i + len];

        if let Some(tag) = PhyTag::from_u8(tag_byte) {
            match tag {
                PhyTag::VidPid => {
                    if val.len() == 4 {
                        let vid = u16::from_be_bytes([val[0], val[1]]);
                        let pid = u16::from_be_bytes([val[2], val[3]]);
                        config.vid = format!("{:04X}", vid);
                        config.pid = format!("{:04X}", pid);
                    }
                }
                PhyTag::LedGpio => {
                    if !val.is_empty() {
                        config.led_gpio = val[0];
                    }
                }
                PhyTag::LedBrightness => {
                    if !val.is_empty() {
                        config.led_brightness = val[0];
                    }
                }
                PhyTag::PresenceTimeout => {
                    if !val.is_empty() {
                        config.touch_timeout = val[0];
                    }
                }
                PhyTag::UsbProduct => {
                    let s = std::str::from_utf8(val)
                        .unwrap_or("")
                        .trim_matches(char::from(0));
                    config.product_name = s.to_string();
                }
                PhyTag::Opts => {
                    if val.len() >= 2 {
                        let opts_val = u16::from_be_bytes([val[0], val[1]]);
                        let opts = RescueOptions::from_bits_truncate(opts_val);

                        config.led_dimmable = opts.contains(RescueOptions::LED_DIMMABLE);
                        config.power_cycle_on_reset =
                            !opts.contains(RescueOptions::DISABLE_POWER_RESET);
                        config.led_steady = opts.contains(RescueOptions::LED_STEADY);
                    }
                }
                PhyTag::Curves => {
                    if val.len() == 4 {
                        let curves_val = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
                        config.raw_curves_mask = Some(curves_val);
                        let curves = RescueCurves::from_bits_truncate(curves_val);
                        config.enable_secp256k1 = curves.contains(RescueCurves::SECP256K1);
                    }
                }
                PhyTag::LedDriver => {
                    if !val.is_empty() {
                        config.led_driver = Some(val[0]);
                    }
                }
                PhyTag::LedOrder => {
                    if !val.is_empty() {
                        config.led_order = Some(val[0]);
                    }
                }
                PhyTag::EnabledUsbItf => {
                    if !val.is_empty() {
                        config.enabled_usb_itf = Some(val[0]);
                    }
                }
            }
        }
        i += len;
    }

    log::info!(
        "Successfully read device details - Serial: {}, Firmware: {}.{}",
        serial_str,
        version_major,
        version_minor
    );

    Ok(FullDeviceStatus {
        info: DeviceInfo {
            serial: serial_str,
            flash_used: Some(used / 1024),
            flash_total: Some(total / 1024),
            firmware_version: format!("{}.{}", version_major, version_minor),
        },
        config,
        secure_boot: sb_enabled,
        secure_lock: sb_locked,
        method: DeviceMethod::Rescue,
        firmware_type: fw_type,
    })
}

pub fn write_config(config: AppConfigInput) -> Result<String, PFError> {
    log::info!("Writing configuration to device");
    log::debug!("Config input: {:?}", config);

    // 1. Construct TLV Blob
    let mut tlv = Vec::new();

    // VID:PID (Tag 0x00)
    if let (Some(vid_str), Some(pid_str)) = (&config.vid, &config.pid) {
        let vid =
            u16::from_str_radix(vid_str, 16).map_err(|_| PFError::Io("Invalid VID".into()))?;
        let pid =
            u16::from_str_radix(pid_str, 16).map_err(|_| PFError::Io("Invalid PID".into()))?;

        tlv.push(PhyTag::VidPid as u8);
        tlv.push(0x04);
        tlv.write_u16::<BigEndian>(vid).unwrap();
        tlv.write_u16::<BigEndian>(pid).unwrap();
    }

    // LED GPIO (Tag 0x04)
    if let Some(val) = config.led_gpio {
        tlv.push(PhyTag::LedGpio as u8);
        tlv.push(0x01);
        tlv.push(val);
    }

    // LED Brightness (Tag 0x05)
    if let Some(val) = config.led_brightness {
        tlv.push(PhyTag::LedBrightness as u8);
        tlv.push(0x01);
        tlv.push(val);
    }

    // Touch Timeout (Tag 0x08)
    if let Some(val) = config.touch_timeout {
        tlv.push(PhyTag::PresenceTimeout as u8);
        tlv.push(0x01);
        tlv.push(val);
    }

    // Options
    if let (Some(dim), Some(cycle), Some(steady)) = (
        config.led_dimmable,
        config.power_cycle_on_reset,
        config.led_steady,
    ) {
        let mut opts = RescueOptions::empty();
        if dim {
            opts.insert(RescueOptions::LED_DIMMABLE);
        }
        if !cycle {
            opts.insert(RescueOptions::DISABLE_POWER_RESET);
        }
        if steady {
            opts.insert(RescueOptions::LED_STEADY);
        }

        tlv.push(PhyTag::Opts as u8);
        tlv.push(0x02);
        tlv.write_u16::<BigEndian>(opts.bits()).unwrap();
    }

    // Curves
    if config.enable_secp256k1.is_some() || config.raw_curves_mask.is_some() {
        let mut mask = config.raw_curves_mask.unwrap_or(0);
        if let Some(enabled) = config.enable_secp256k1 {
            if enabled {
                mask |= RescueCurves::SECP256K1.bits();
            } else {
                mask &= !RescueCurves::SECP256K1.bits();
            }
        }
        tlv.push(PhyTag::Curves as u8);
        tlv.push(0x04);
        tlv.write_u32::<BigEndian>(mask).unwrap();
    }

    // LED Driver (Tag 0x0C)
    if let Some(val) = config.led_driver {
        tlv.push(PhyTag::LedDriver as u8);
        tlv.push(0x01);
        tlv.push(val);
    }

    // Product Name (Tag 0x09)
    if let Some(name) = config.product_name.filter(|n| !n.is_empty()) {
        let name_bytes = name.as_bytes();
        let len = name_bytes.len() + 1;
        if len > 32 {
            return Err(PFError::Io("Product name too long".into()));
        }

        tlv.push(PhyTag::UsbProduct as u8);
        tlv.push(len as u8);
        tlv.extend_from_slice(name_bytes);
        tlv.push(0x00);
    }

    // LED Order (Tag 0x0D) — RS-Key extension, silently preserved
    if let Some(val) = config.led_order {
        tlv.push(PhyTag::LedOrder as u8);
        tlv.push(0x01);
        tlv.push(val);
    }

    // Enabled USB Interfaces (Tag 0x0B)
    if let Some(val) = config.enabled_usb_itf {
        tlv.push(PhyTag::EnabledUsbItf as u8);
        tlv.push(0x01);
        // SAFETY: Never write a mask without CCID, otherwise Rescue applet is unreachable.
        tlv.push(val | UsbInterfaces::CCID.bits());
    }

    // 2. Connect and Send
    if tlv.is_empty() {
        log::warn!("No configuration changes to apply");
        return Ok("No changes to apply".into());
    }

    log::debug!("TLV payload size: {} bytes", tlv.len());

    let (card, _, _) = connect_and_select()?;

    // APDU: 80 1C 01 00 [Lc] [Data]
    let mut apdu = vec![
        APDU_CLA_PROPRIETARY,
        RescueInstruction::Write as u8,
        WriteParam::PhyConfig as u8,
        P2_UNUSED,
        tlv.len() as u8, // Lc
    ];
    apdu.extend_from_slice(&tlv);

    let mut rx_buf = [0; 256];
    let rx = card.transmit(&apdu, &mut rx_buf)?;

    if rx.ends_with(&[0x90, 0x00]) {
        log::info!("Configuration applied successfully");
        Ok("Configuration Applied Successfully".into())
    } else {
        log::error!("Configuration write failed: {:02X?}", rx);
        Err(PFError::Device(format!("Write failed: {:02X?}", rx)))
    }
}

pub fn reboot_device(to_bootsel: bool) -> Result<String, PFError> {
    let (card, _, _) = connect_and_select()?;

    let param = if to_bootsel {
        RebootParam::Bootsel
    } else {
        RebootParam::Normal
    };

    let apdu = [
        APDU_CLA_PROPRIETARY,
        RescueInstruction::Reboot as u8,
        param as u8,
        P2_UNUSED,
        0x00,
    ];

    let mut rx_buf = [0; 256];
    let rx = card.transmit(&apdu, &mut rx_buf)?;

    if rx.ends_with(&SW_SUCCESS) {
        Ok("Reboot command sent".into())
    } else {
        Err(PFError::Device(format!("Reboot failed: {:02X?}", rx)))
    }
}

/// UNSTABLE! (WIP)
pub fn enable_secure_boot(lock: bool) -> Result<String, PFError> {
    let (card, _, _) = connect_and_select()?;

    // APDU: 80 1D [KeyIndex] [LockBool] 00
    // KeyIndex = 0 (Default), LockBool = 1 if true
    let lock_byte = if lock { 0x01 } else { 0x00 };

    let apdu = [
        APDU_CLA_PROPRIETARY,
        RescueInstruction::Secure as u8,
        0x00, // Boot Key Index (0 = Default)
        lock_byte as u8,
        0x00,
    ];

    let mut rx_buf = [0; 256];
    let rx = card.transmit(&apdu, &mut rx_buf)?;

    if rx.ends_with(&[0x90, 0x00]) {
        Ok("Secure Boot Enabled".into())
    } else {
        Err(PFError::Device(format!("Secure Boot failed: {:02X?}", rx)))
    }
}

// --- Vendor/LED Applet (RS-Key) ---

fn connect_and_select_aid(aid: &[u8]) -> Result<pcsc::Card, PFError> {
    let ctx = Context::establish(Scope::User).map_err(|e| {
        log::error!("Failed to establish PCSC context: {}", e);
        PFError::Pcsc(e)
    })?;

    let mut readers_buf = [0; 2048];
    let mut readers = ctx.list_readers(&mut readers_buf)?;
    let reader = readers.next().ok_or_else(|| {
        log::info!("No Smart Card Reader found");
        PFError::NoDevice
    })?;

    let card = ctx.connect(reader, ShareMode::Shared, Protocols::ANY)?;

    let mut apdu = vec![
        APDU_CLA_ISO,
        APDU_INS_SELECT,
        APDU_P1_SELECT_BY_DF_NAME,
        0x00,
        aid.len() as u8,
    ];
    apdu.extend_from_slice(aid);
    apdu.push(0x00);

    let mut rx_buf = [0; 256];
    let rx = card.transmit(&apdu, &mut rx_buf)?;

    if !rx.ends_with(&[0x90, 0x00]) {
        return Err(PFError::Device(format!(
            "Applet not found (AID {:02X?})",
            aid
        )));
    }

    Ok(card)
}

/// Reads the customized LED status configurations from the Vendor/LED applet.
///
/// Communicates with the `F0 00 00 00 01` applet to retrieve a 9-byte configuration block
/// that dictates the color and brightness for each device state (idle, processing, touch, boot),
/// as well as the global 'steady' toggle flag.
pub fn read_led_config() -> Result<LedStatusConfig, PFError> {
    log::info!("Reading LED status config from Vendor/LED applet");
    let card = connect_and_select_aid(VENDOR_LED_AID)?;

    let apdu = [
        APDU_CLA_ISO,
        VendorLedInstruction::GetLed as u8,
        0x00,
        0x00,
        0x00,
    ];
    let mut rx_buf = [0; 256];
    let rx = card.transmit(&apdu, &mut rx_buf)?;

    if !rx.ends_with(&SW_SUCCESS) || rx.len() < 11 {
        return Err(PFError::Device("Failed to read LED config".into()));
    }

    let data = &rx[..rx.len() - 2];
    if data.len() < 9 {
        return Err(PFError::Device("LED config response too short".into()));
    }

    let steady = data[0] != 0;
    let mut statuses = [(0u8, 0u8); 4];
    for s in 0..4 {
        statuses[s] = (data[1 + 2 * s], data[2 + 2 * s]);
    }

    log::info!("LED config: steady={}, statuses={:?}", steady, statuses);
    Ok(LedStatusConfig { steady, statuses })
}

/// Applies an individual LED status update to the Vendor/LED applet.
///
/// Constructs the APDU payload combining the targeted status index, color code, and global
/// steady flag into `P2`, with the brightness value in `P1`. The update is persisted to flash
/// and applied immediately.
pub fn write_led_status(
    status: u8,
    color: u8,
    brightness: u8,
    steady: bool,
) -> Result<String, PFError> {
    log::info!(
        "Setting LED: status={}, color={}, brightness={}, steady={}",
        status,
        color,
        brightness,
        steady
    );
    let card = connect_and_select_aid(VENDOR_LED_AID)?;

    let steady_bit: u8 = if steady { 0x08 } else { 0x00 };
    let p2 = (color & 0x07) | steady_bit | ((status & 0x03) << 4);

    let apdu = [
        APDU_CLA_ISO,
        VendorLedInstruction::SetLed as u8,
        brightness,
        p2,
    ];
    let mut rx_buf = [0; 256];
    let rx = card.transmit(&apdu, &mut rx_buf)?;

    if rx.ends_with(&SW_SUCCESS) {
        Ok("LED status updated".into())
    } else {
        Err(PFError::Device(format!("SET LED failed: {:02X?}", rx)))
    }
}

// --- Management Applet (RS-Key) ---

/// Retrieves the device management configuration mapping from the Management applet.
///
/// Reads the active state of various USB interfaces (U2F, OATH, PIV, OpenPGP, etc.) to
/// determine which are supported by the hardware and which are currently enabled by the user.
pub fn read_management_config() -> Result<ManagementAppConfig, PFError> {
    log::info!("Reading management config from Management applet");
    let card = connect_and_select_aid(MANAGEMENT_AID)?;

    let apdu = [
        APDU_CLA_ISO,
        ManagementInstruction::ReadConfig as u8,
        0x00,
        0x00,
        0x00,
    ];
    let mut rx_buf = [0; 256];
    let rx = card.transmit(&apdu, &mut rx_buf)?;

    if !rx.ends_with(&SW_SUCCESS) {
        return Err(PFError::Device("Failed to read management config".into()));
    }

    let data = &rx[..rx.len() - 2];
    if data.is_empty() {
        return Err(PFError::Device("Empty management config response".into()));
    }

    let overall_len = data[0] as usize;
    let tlv_data = if data.len() > 1 + overall_len {
        &data[1..1 + overall_len]
    } else {
        &data[1..]
    };

    let mut config = ManagementAppConfig::default();
    let mut i = 0;
    while i < tlv_data.len() {
        if i + 2 > tlv_data.len() {
            break;
        }
        let tag = tlv_data[i];
        let len = tlv_data[i + 1] as usize;
        i += 2;
        if i + len > tlv_data.len() {
            break;
        }
        let val = &tlv_data[i..i + len];
        match tag {
            MGMT_TAG_USB_SUPPORTED => {
                if val.len() >= 2 {
                    config.usb_supported = u16::from_be_bytes([val[0], val[1]]);
                }
            }
            MGMT_TAG_USB_ENABLED => {
                if val.len() >= 2 {
                    config.usb_enabled = u16::from_be_bytes([val[0], val[1]]);
                }
            }
            _ => {
                log::trace!("Management TLV tag 0x{:02X} skipped", tag);
            }
        }
        i += len;
    }

    log::info!(
        "Management config: supported=0x{:04X}, enabled=0x{:04X}",
        config.usb_supported,
        config.usb_enabled
    );
    Ok(config)
}

/// Persists updated management endpoint configurations to the device.
///
/// Overwrites the previously enabled interfaces with a new configuration bitmask.
/// For the changes to fully apply across all composite USB endpoints, a subsequent
/// device reboot or re-plug is required.
pub fn write_management_config(enabled_mask: u16) -> Result<String, PFError> {
    log::info!("Writing management config: enabled=0x{:04X}", enabled_mask);
    let card = connect_and_select_aid(MANAGEMENT_AID)?;

    let inner = [
        MGMT_TAG_USB_ENABLED,
        0x02,
        (enabled_mask >> 8) as u8,
        (enabled_mask & 0xFF) as u8,
    ];

    let mut apdu = vec![
        APDU_CLA_ISO,
        ManagementInstruction::WriteConfig as u8,
        0x00,
        0x00,
        (inner.len() + 1) as u8,
        inner.len() as u8,
    ];
    apdu.extend_from_slice(&inner);

    let mut rx_buf = [0; 256];
    let rx = card.transmit(&apdu, &mut rx_buf)?;

    if rx.ends_with(&SW_SUCCESS) {
        Ok("USB applications updated".into())
    } else {
        Err(PFError::Device(format!(
            "Management write failed: {:02X?}",
            rx
        )))
    }
}
