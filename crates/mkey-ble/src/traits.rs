//! BLE transport trait definitions.
//!
//! Defines the abstract interface for BLE communication with SALTO locks.

use mkey_core::{Error, ProtocolFlags};
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

    /// Enable notifications on the notify characteristic (CCCD).
    ///
    /// Must be idempotent: the session layer calls it once per exchange and
    /// does not track whether a previous call already subscribed.
    ///
    /// Ordering matters. The lock starts driving the exchange as soon as
    /// notifications are enabled, so everything the phone wants to do first —
    /// version detection above all — has to happen before this call, and the
    /// implementation has to have the notification sink in place before the
    /// CCCD write, or the first packet is lost.
    async fn subscribe(&mut self) -> Result<(), Error>;

    /// Read the notify characteristic directly.
    ///
    /// Used only for protocol info (`01 <minor> <major>`) during version
    /// detection, before notifications are enabled.
    async fn read_notify_value(&mut self) -> Result<Vec<u8>, Error>;

    /// Whether the notify characteristic advertises the READ property.
    ///
    /// When it does not, the protocol info cannot be read and the version
    /// stays unknown; the session then runs the v0200 flow.
    fn notify_readable(&self) -> bool;
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
