//! SALTO KS mobile key, in Rust.
//!
//! This crate is a facade. The code lives in four crates under `crates/`,
//! split along the line between "decides bytes" and "moves bytes":
//!
//! | crate | what it is | targets |
//! |---|---|---|
//! | [`mkey_core`] | the protocol: crypto, key codec, SSP, Justin. No I/O. | any, including wasm |
//! | [`mkey_session`] | one opening attempt as a pure state machine | any, including wasm |
//! | [`mkey_ble`] | the native shell: transport trait, btleplug, the pump | native |
//! | [`mkey_sdk_virgil`] | provisioning: Virgil container, keystore | native |
//!
//! Everything the crate exported before the split is still exported from here
//! under the same path.

pub use mkey_core::{advertisement, command, crypto, data, error, security, stack};
pub use mkey_core::{
    parse_salto_advertisement, CommandStatus, Error, ErrorCode, MobileKey, ProtocolFlags, Rf3State,
    SaltoAdvertisement, SALTO_MANUFACTURER_ID,
};

/// One opening attempt as a pure state machine — the protocol's decisions,
/// with no I/O in them.
pub use mkey_session as session;
pub use mkey_session::{Detection, Outcome, Phase, Timeouts, Trace};

#[cfg(feature = "ble")]
pub use mkey_ble as ble;
#[cfg(feature = "ble")]
pub use mkey_ble::{
    run_session, BleTransport, BtleplugTransport, ConnectedLock, DiscoveredLock, HandshakePlan,
    LockFilter, LockState, OpeningMode, SaltoLock, SessionObserver, StderrObserver,
    SALTO_NOTIFY_UUID, SALTO_SERVICE_UUID, SALTO_WRITE_UUID,
};

#[cfg(feature = "sdk")]
pub mod sdk;
