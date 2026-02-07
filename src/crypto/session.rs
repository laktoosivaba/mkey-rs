/// Derive session key from RandomA and RandomB
///
/// Used after successful SSP authentication (AUTH_STEP_2) to create
/// the session key that replaces kN for subsequent communications.
///
/// # Arguments
/// * `random_a` - 16-byte random value from lock
/// * `random_b` - 16-byte random value from phone
///
/// # Returns
/// 16-byte session key
pub fn derive_session_key(random_a: &[u8; 16], random_b: &[u8; 16]) -> [u8; 16] {
    let mut session_key = [0u8; 16];
    session_key[0..4].copy_from_slice(&random_a[0..4]);
    session_key[4..8].copy_from_slice(&random_b[0..4]);
    session_key[8..12].copy_from_slice(&random_a[12..16]);
    session_key[12..16].copy_from_slice(&random_b[12..16]);
    session_key
}
