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

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS-197 Appendix C.1 (AES-128). With an all-zero IV a single-block CBC
    /// encryption is identical to ECB, so this is an external reference value.
    const FIPS_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const FIPS_PLAINTEXT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const FIPS_CIPHERTEXT: &str = "69c4e0d86a7b0430d8cdb78070b4c55a";

    #[test]
    fn matches_the_fips197_vector_with_a_zero_iv() {
        let ciphertext = encrypt_aes_cbc(&FIPS_KEY, &[0u8; 16], &FIPS_PLAINTEXT);
        assert_eq!(hex::encode(&ciphertext), FIPS_CIPHERTEXT);
    }

    #[test]
    fn decrypt_inverts_encrypt() {
        let key = [0x2bu8; 16];
        let iv = [0x99u8; 16];
        let plaintext: Vec<u8> = (0..48u8).collect();
        let ciphertext = encrypt_aes_cbc(&key, &iv, &plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());
        assert_eq!(decrypt_aes_cbc(&key, &iv, &ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn the_iv_chains_across_blocks() {
        // Encrypting two blocks at once equals encrypting the second block with
        // the first block's ciphertext as IV — the property the SSP IV chain
        // relies on.
        let key = [0x5eu8; 16];
        let iv = [0u8; 16];
        let block_a = [0x01u8; 16];
        let block_b = [0x02u8; 16];
        let together = encrypt_aes_cbc(&key, &iv, &[block_a, block_b].concat());

        let first = encrypt_aes_cbc(&key, &iv, &block_a);
        let mut chained_iv = [0u8; 16];
        chained_iv.copy_from_slice(&first);
        let second = encrypt_aes_cbc(&key, &chained_iv, &block_b);

        assert_eq!(together, [first, second].concat());
    }

    #[test]
    fn the_v0100_signing_iv_is_sixteen_ff_bytes() {
        let nonce = [0x42u8; 16];
        let signed = encrypt_aes_cbc(&FIPS_KEY, &[0xFFu8; 16], &nonce);
        assert_eq!(signed.len(), 16);
        // XOR-then-encrypt: the same result as encrypting `nonce ^ FF..` with a zero IV.
        let xored: Vec<u8> = nonce.iter().map(|b| b ^ 0xFF).collect();
        assert_eq!(signed, encrypt_aes_cbc(&FIPS_KEY, &[0u8; 16], &xored));
    }

    #[test]
    fn a_short_ciphertext_is_rejected() {
        assert!(decrypt_aes_cbc(&FIPS_KEY, &[0u8; 16], &[0u8; 5]).is_err());
    }
}
