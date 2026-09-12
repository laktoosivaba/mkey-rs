//! Turning platform GATT failures into the shared error vocabulary.
//!
//! The browser port does the same thing in `transport/gatt-errors.ts`: a
//! platform error is not something the protocol can reason about, so it is
//! flattened to `gatt-operation-failed` with the platform's own message kept
//! as the detail, and a word about which call failed.

#[cfg(feature = "btleplug")]
use mkey_core::Error;

#[cfg(feature = "btleplug")]
pub(crate) trait GattContext<T> {
    /// Attach the name of the operation and map to [`Error::GattOperationFailed`].
    fn gatt(self, what: &str) -> Result<T, Error>;
}

#[cfg(feature = "btleplug")]
impl<T> GattContext<T> for Result<T, btleplug::Error> {
    fn gatt(self, what: &str) -> Result<T, Error> {
        self.map_err(|e| Error::GattOperationFailed(format!("{what} failed: {e}")))
    }
}
