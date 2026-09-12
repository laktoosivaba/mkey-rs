#[cfg(feature = "sdk-virgil")]
mod virgil;

#[cfg(feature = "sdk-virgil")]
pub use virgil::{
    decrypt_virgil_private_key, derive_virgil_public_key, encrypt_virgil_private_key,
    generate_rsa_private_key, generate_virgil_key_pair, roundtrip_virgil_public_key, VirgilKeyPair,
    RSA_KEY_BITS,
};

use std::time::Duration;

use crate::data::mobile_key::MobileKey;
use crate::lock::{OpeningMode, SaltoLock};
use crate::transport::LockFilter;
use crate::Error;

/// Scan for a SALTO lock, connect, authenticate, and open.
///
/// This is the main high-level entry point for opening a lock with an
/// already-decoded mobile key.
///
/// # Arguments
/// * `mobile_key` — a parsed `MobileKey`
/// * `lock_name` — optional lock name filter (connects to first matching lock)
/// * `mode` — `OpeningMode::Standard` or `OpeningMode::Office`
/// * `scan_timeout` — maximum time to scan for a lock (default: 30s)
pub async fn open(
    mobile_key: MobileKey,
    lock_name: Option<&str>,
    mode: OpeningMode,
    scan_timeout: Option<Duration>,
) -> Result<(), Error> {
    let mut lock = SaltoLock::new().await?;

    let filter: Option<LockFilter> = lock_name.map(|name| {
        let name = name.to_string();
        Box::new(move |l: &crate::transport::DiscoveredLock| {
            l.name.as_deref() == Some(name.as_str())
        }) as LockFilter
    });

    let timeout = scan_timeout.or(Some(Duration::from_secs(30)));
    lock.scan_and_connect_filtered(timeout, filter).await?;
    lock.authenticate(mobile_key).await?;
    lock.open_with_mode(mode).await?;

    Ok(())
}

/// Decode a Virgil-encrypted mobile key.
///
/// The Virgil WASM crypto library is embedded in the crate.
///
/// # Arguments
/// * `rsa_private_key_der` — RSA private key in PKCS8 DER format
/// * `encrypted_virgil_key` — RSA-encrypted (base64-wrapped) Virgil EC private key
/// * `encrypted_mkey_data` — raw bytes of the Virgil encrypted container
///
/// # Returns
/// A parsed `MobileKey` on success.
#[cfg(feature = "sdk-virgil")]
pub fn decode(
    rsa_private_key_der: &[u8],
    encrypted_virgil_key: &[u8],
    encrypted_mkey_data: &[u8],
) -> Result<MobileKey, Error> {
    virgil::decrypt_mobile_key(
        rsa_private_key_der,
        encrypted_virgil_key,
        encrypted_mkey_data,
    )
}

/// Decode a Virgil-encrypted mobile key, then open the lock.
///
/// Combines `decode` and `open` into a single call.
#[cfg(feature = "sdk-virgil")]
pub async fn open_encoded(
    rsa_private_key_der: &[u8],
    encrypted_virgil_key: &[u8],
    encrypted_mkey_data: &[u8],
    lock_name: Option<&str>,
    mode: OpeningMode,
    scan_timeout: Option<Duration>,
) -> Result<(), Error> {
    let mobile_key = decode(
        rsa_private_key_der,
        encrypted_virgil_key,
        encrypted_mkey_data,
    )?;
    open(mobile_key, lock_name, mode, scan_timeout).await
}
