//! One SALTO KS opening attempt, as a pure state machine.
//!
//! The protocol is the same everywhere; the way bytes are moved is not. This
//! crate keeps the first part and refuses the second: [`Session::poll`] takes
//! an [`Event`] and returns the [`Action`]s the shell must carry out, and that
//! is the entire interface. No futures, no callbacks, no traits to implement —
//! the pattern `quinn`, `rustls` and `h2` use, for the same reason: the
//! decisions are testable without a network, and the same decisions run behind
//! a native Bluetooth stack and inside a browser.
//!
//! ```no_run
//! # use mkey_core::MobileKey;
//! # use mkey_session::{Action, Event, Options, Session};
//! # fn apply(_: &Action) {}
//! # fn next_event<'a>() -> Event<'a> { Event::Started }
//! # let key = MobileKey::new([0u8; 16]);
//! let mut session = Session::new(key, Options::default());
//! let mut event = Event::Started;
//!
//! loop {
//!     let actions = session.poll(event);
//!
//!     for action in &actions {
//!         if let Action::Done(result) = action {
//!             println!("{result:?}");
//!             return;
//!         }
//!
//!         apply(action);
//!     }
//!
//!     event = next_event();
//! }
//! ```
//!
//! What the shell owes the session is written out on [`Session`]. The short
//! version: apply actions in order, keep at most one timer, queue notifications
//! that arrive meanwhile, and own the disconnect.

mod session;
mod types;

pub use session::{Session, APP_PROTOCOL_REQUEST, LOCK_DISCONNECTED_MESSAGE};
pub use types::{
    Action, Detection, Event, Mode, Options, Outcome, Phase, Timeouts, TimerId, Trace,
};

pub use mkey_core::{Error, ErrorCode, MobileKey, OpResultGroup};
