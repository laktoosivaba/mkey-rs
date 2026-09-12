//! The SALTO KS protocol, with no I/O in it.
//!
//! Everything here is a pure function or a state machine over bytes: the
//! crypto primitives, the mobile key codec, the SSP secure channel and the
//! Justin command layer. Nothing in this crate opens a socket, reads a clock
//! or awaits anything, which is what lets the same code run behind a native
//! Bluetooth stack and inside a browser.

pub mod advertisement;
pub mod command;
pub mod crypto;
pub mod data;
pub mod error;
pub mod security;
pub mod stack;

pub use advertisement::{
    parse_salto_advertisement, ProtocolFlags, Rf3State, SaltoAdvertisement, SALTO_MANUFACTURER_ID,
};
pub use data::mobile_key::MobileKey;
pub use error::{CommandStatus, Error, ErrorCode};
