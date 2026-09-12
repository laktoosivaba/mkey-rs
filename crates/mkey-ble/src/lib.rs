//! The native I/O shell around the SALTO KS protocol.
//!
//! Three layers, deliberately separable:
//!
//! * [`BleTransport`] — what the session needs from a radio, and nothing more.
//! * [`BtleplugTransport`] — that trait over a real adapter (feature `btleplug`).
//! * [`SaltoLock`] — the session driver: connect, work out the protocol
//!   version, run the exchange. Generic over the transport, so the same driver
//!   runs against an in-process simulator.
//!
//! Turn the `btleplug` feature off and what remains is the trait plus the
//! driver — enough to drive a session over something that is not a radio.

pub mod advertisement;
#[cfg(feature = "btleplug")]
mod btleplug_impl;
#[cfg(feature = "btleplug")]
mod gatt;
pub mod lock;
mod pump;
mod traits;

pub use advertisement::{discover_by_manufacturer_data, discover_by_service_uuid};
#[cfg(feature = "btleplug")]
pub use btleplug_impl::BtleplugTransport;
pub use lock::{HandshakePlan, LockState, OpeningMode, SaltoLock, StderrObserver};
pub use pump::{run_session, SessionObserver};
pub use traits::{
    BleTransport, ConnectedLock, DiscoveredLock, LockFilter, Notification, SALTO_NOTIFY_UUID,
    SALTO_SERVICE_UUID, SALTO_WRITE_UUID,
};

/// The failure vocabulary is shared with the protocol core; the transport
/// contributes the connection-level variants rather than an error type of its own.
pub use mkey_core::{Error, ErrorCode, ProtocolFlags, Rf3State, SALTO_MANUFACTURER_ID};
pub use mkey_session::{Detection, Options, Outcome, Phase, Session, Timeouts, Trace};
