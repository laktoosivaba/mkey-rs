//! BLE transport trait definitions.
//!
//! Defines the abstract interface for BLE communication with SALTO locks.

use crate::Error;
use std::time::Duration;

/// Information about a discovered SALTO lock.
#[derive(Debug, Clone)]
pub struct DiscoveredLock {
    /// The peripheral identifier (platform-specific).
    pub id: String,
    /// The local name advertised by the lock (if available).
    pub name: Option<String>,
    /// The RSSI (signal strength) at discovery time.
    pub rssi: Option<i16>,
    /// Protocol version from advertisement.
    pub protocol_version: u8,
    /// Protocol flags from advertisement.
    pub flags: ProtocolFlags,
}

/// Represents an active connection to a SALTO lock.
///
/// This type is returned by `scan_and_connect` and `connect_by_id` methods.
/// It is not `Clone` as it represents exclusive ownership of the connection state.
#[derive(Debug)]
pub struct ConnectedLock {
    /// Information about the connected lock.
    pub info: DiscoveredLock,
}

/// Protocol flags parsed from SALTO advertisement data.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProtocolFlags {
    /// Proximity mode: false = NEAR, true = REMOTE
    pub remote: bool,
    /// Messages available: false = NO_MESSAGES, true = WITH_MESSAGES
    pub has_messages: bool,
    /// RF3 state
    pub rf3_state: Rf3State,
}

impl ProtocolFlags {
    /// Parse protocol flags from the advertisement byte.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            remote: (byte & 0x01) != 0,
            has_messages: (byte & 0x04) != 0,
            rf3_state: Rf3State::from_bits((byte >> 4) & 0x03),
        }
    }
}

/// RF3 state from advertisement flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Rf3State {
    #[default]
    Off = 0,
    Ini = 1,
    Link = 2,
    Lost = 3,
}

impl Rf3State {
    fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Self::Off,
            1 => Self::Ini,
            2 => Self::Link,
            3 => Self::Lost,
            _ => Self::Off,
        }
    }
}

/// Notification received from the lock.
#[derive(Debug, Clone)]
pub struct Notification {
    /// The raw data bytes received.
    pub data: Vec<u8>,
}

/// Filter function type for scan_and_connect.
pub type LockFilter = Box<dyn Fn(&DiscoveredLock) -> bool + Send + Sync>;

/// Abstract trait for BLE transport operations.
///
/// This trait defines the interface for BLE communication with SALTO locks,
/// allowing for different implementations (btleplug, mock, etc.).
#[allow(async_fn_in_trait)]
pub trait BleTransport {
    /// Scan for SALTO locks.
    async fn scan(&self, duration: Duration) -> Result<Vec<DiscoveredLock>, Error>;

    /// Scan for a SALTO lock and connect immediately when found.
    async fn scan_and_connect(
        &mut self,
        timeout: Duration,
        filter: Option<LockFilter>,
    ) -> Result<ConnectedLock, Error>;

    /// Connect to a previously discovered lock by its ID.
    async fn connect_by_id(
        &mut self,
        lock_id: &str,
        timeout: Duration,
    ) -> Result<ConnectedLock, Error>;

    /// Disconnect from the currently connected lock.
    async fn disconnect(&mut self) -> Result<(), Error>;

    /// Check if currently connected.
    fn is_connected(&self) -> bool;

    /// Write data to the lock.
    async fn write(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Receive the next notification from the lock.
    async fn receive(&mut self) -> Result<Option<Notification>, Error>;
}

/// SALTO BLE GATT service UUID.
pub const SALTO_SERVICE_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0xB6E60001_E2E3_BC82_4C72_929D0D29CA17);

/// SALTO BLE notify characteristic UUID (Lock → Phone).
pub const SALTO_NOTIFY_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0xB6E60002_E2E3_BC82_4C72_929D0D29CA17);

/// SALTO BLE write characteristic UUID (Phone → Lock).
pub const SALTO_WRITE_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(0xB6E60003_E2E3_BC82_4C72_929D0D29CA17);

/// SALTO manufacturer ID bytes in advertisement data.
/// Company ID is 0x0199 (little-endian: 0x99, 0x01).
pub const SALTO_MANUFACTURER_ID: u16 = 0x0199;
