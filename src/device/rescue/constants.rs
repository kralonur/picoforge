//! Constants, enums, bitflags and data structures for Rescue and vendor applets.
#![allow(unused)]

// use serde::{Deserialize, Serialize};
// use std::fmt;

// --- 1. ISO 7816-4 Standard Constants ---

/// Class Byte (CLA)
pub const APDU_CLA_ISO: u8 = 0x00; // Standard ISO commands
pub const APDU_CLA_PROPRIETARY: u8 = 0x80; // Custom/Rescue commands

/// Instruction (INS) for Selection
pub const APDU_INS_SELECT: u8 = 0xA4;

/// Selection Parameters (P1, P2)
pub const APDU_P1_SELECT_BY_DF_NAME: u8 = 0x04;
pub const APDU_P2_RETURN_FCI: u8 = 0x04; // Return File Control Info

/// Status Words (SW1 SW2)
pub const SW_SUCCESS: [u8; 2] = [0x90, 0x00];

// --- 2. Rescue Applet Constants ---

// The Rescue Application ID (AID) from src/rescue.c
pub const RESCUE_AID: &[u8] = &[0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21];

// APDU Instructions
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RescueInstruction {
    KeyDevSign = 0x10,
    Write = 0x1C,
    Secure = 0x1D,
    Read = 0x1E,
    Reboot = 0x1F,
}

/// P1 Parameters for RescueInstruction::Read (0x1E)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadParam {
    PhyConfig = 0x01,
    FlashInfo = 0x02,
    SecureBootStatus = 0x03,
}

/// P1 Parameters for WRITE (0x1C)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteParam {
    PhyConfig = 0x01,
}

/// P1 Parameters for RescueInstruction::KeyDevSign (0x10)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignParam {
    SignData = 0x01,
    GetPublicKey = 0x02,
    UploadCert = 0x03,
}

/// P1 Parameters for RescueInstruction::Reboot (0x1F)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootParam {
    Normal = 0x00,
    Bootsel = 0x01,
}

/// P2 Parameters for SECURE (0x1D)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecureLockParam {
    #[default]
    Unlock = 0x00,
    Lock = 0x01,
}

/// Default P2 value when not used
pub const P2_UNUSED: u8 = 0x00;

// --- 3. PHY Configuration Tags & Flags ---

// PHY Tags from src/fs/phy.h
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhyTag {
    VidPid = 0x00,
    LedGpio = 0x04,
    LedBrightness = 0x05,
    Opts = 0x06,
    PresenceTimeout = 0x08,
    UsbProduct = 0x09,
    Curves = 0x0A,
    LedDriver = 0x0C,
    LedOrder = 0x0D,
}

impl PhyTag {
    /// Helper to convert raw u8 from device back to Enum
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::VidPid),
            0x04 => Some(Self::LedGpio),
            0x05 => Some(Self::LedBrightness),
            0x06 => Some(Self::Opts),
            0x08 => Some(Self::PresenceTimeout),
            0x09 => Some(Self::UsbProduct),
            0x0A => Some(Self::Curves),
            0x0C => Some(Self::LedDriver),
            0x0D => Some(Self::LedOrder),
            _ => None,
        }
    }
}

bitflags::bitflags! {
    /// Configuration options for TAG_OPTS (Tag 0x06)
    pub struct RescueOptions: u16 {
        const LED_DIMMABLE = 0x02;
        const DISABLE_POWER_RESET = 0x04;
        const LED_STEADY = 0x08;
    }
}

bitflags::bitflags! {
    /// Enabled curves for TAG_CURVES (Tag 0x0A)
    pub struct RescueCurves: u32 {
        const SECP256K1 = 0x08;
    }
}

// --- 4. Vendor/LED Applet (RS-Key specific) ---

pub const VENDOR_LED_AID: &[u8] = &[0xF0, 0x00, 0x00, 0x00, 0x01];

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorLedInstruction {
    SetLed = 0x10,
    GetLed = 0x11,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedColor {
    Off = 0,
    Red = 1,
    Green = 2,
    Blue = 3,
    Yellow = 4,
    Magenta = 5,
    Cyan = 6,
    White = 7,
}

impl LedColor {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Off),
            1 => Some(Self::Red),
            2 => Some(Self::Green),
            3 => Some(Self::Blue),
            4 => Some(Self::Yellow),
            5 => Some(Self::Magenta),
            6 => Some(Self::Cyan),
            7 => Some(Self::White),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Red => "Red",
            Self::Green => "Green",
            Self::Blue => "Blue",
            Self::Yellow => "Yellow",
            Self::Magenta => "Magenta",
            Self::Cyan => "Cyan",
            Self::White => "White",
        }
    }

    pub fn all() -> &'static [Self] {
        &[
            Self::Off, Self::Red, Self::Green, Self::Blue,
            Self::Yellow, Self::Magenta, Self::Cyan, Self::White,
        ]
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedStatus {
    Idle = 0,
    Processing = 1,
    Touch = 2,
    Boot = 3,
}

impl LedStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Processing => "Processing",
            Self::Touch => "Touch",
            Self::Boot => "Boot",
        }
    }

    pub fn all() -> &'static [Self] {
        &[Self::Idle, Self::Processing, Self::Touch, Self::Boot]
    }
}

// --- 5. Management Applet (Yubico-compatible, RS-Key) ---

pub const MANAGEMENT_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementInstruction {
    ReadConfig = 0x1D,
    WriteConfig = 0x1C,
}

pub const MGMT_TAG_USB_SUPPORTED: u8 = 0x01;
pub const MGMT_TAG_SERIAL: u8 = 0x02;
pub const MGMT_TAG_USB_ENABLED: u8 = 0x03;
pub const MGMT_TAG_FORM_FACTOR: u8 = 0x04;
pub const MGMT_TAG_VERSION: u8 = 0x05;
pub const MGMT_TAG_DEVICE_FLAGS: u8 = 0x08;
pub const MGMT_TAG_CONFIG_LOCK: u8 = 0x0A;

pub const USB_CAP_OTP: u16 = 0x0001;
pub const USB_CAP_U2F: u16 = 0x0002;
pub const USB_CAP_OPENPGP: u16 = 0x0008;
pub const USB_CAP_PIV: u16 = 0x0010;
pub const USB_CAP_OATH: u16 = 0x0020;
pub const USB_CAP_FIDO2: u16 = 0x0200;
