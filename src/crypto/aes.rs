//! AES-128-CBC encryption and decryption
//!
//! Implements AES-128 in CBC mode with NoPadding (padding handled separately).

use aes::Aes128;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};

/// Encrypts plaintext using AES-128-CBC with NoPadding.
///
/// # Parameters
/// - `key`: 16-byte AES key
/// - `iv`: 16-byte initialization vector
/// - `plaintext`: Data to encrypt (must be multiple of 16 bytes)
///
/// # Returns
/// Encrypted ciphertext
///
/// # Panics
/// Panics if plaintext length is not a multiple of 16 bytes
pub fn encrypt_aes_cbc(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let mut buffer = vec![0u8; plaintext.len()];
    buffer.copy_from_slice(plaintext);

    let cipher = Encryptor::<Aes128>::new(key.into(), iv.into());
    cipher
        .encrypt_padded_mut::<NoPadding>(&mut buffer, plaintext.len())
        .expect("Encryption failed: plaintext length must be multiple of 16")
        .to_vec()
}

/// Decrypts ciphertext using AES-128-CBC with NoPadding.
///
/// # Parameters
/// - `key`: 16-byte AES key
/// - `iv`: 16-byte initialization vector
/// - `ciphertext`: Data to decrypt (must be multiple of 16 bytes)
///
/// # Returns
/// Decrypted plaintext or error
///
/// # Errors
/// Returns `Error::DecryptionFailed` if:
/// - Ciphertext length is not a multiple of 16 bytes
/// - Decryption operation fails
pub fn decrypt_aes_cbc(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, crate::Error> {
    let mut buffer = vec![0u8; ciphertext.len()];
    buffer.copy_from_slice(ciphertext);

    let cipher = Decryptor::<Aes128>::new(key.into(), iv.into());
    let plaintext = cipher
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|_| crate::Error::DecryptionFailed)?;
    Ok(plaintext.to_vec())
}
