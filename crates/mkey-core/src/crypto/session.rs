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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_the_first_and_last_four_bytes_of_each_random() {
        let a: [u8; 16] = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
            0xae, 0xaf,
        ];
        let b: [u8; 16] = [
            0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
            0xbe, 0xbf,
        ];
        assert_eq!(
            derive_session_key(&a, &b),
            [
                0xa0, 0xa1, 0xa2, 0xa3, 0xb0, 0xb1, 0xb2, 0xb3, 0xac, 0xad, 0xae, 0xaf, 0xbc, 0xbd,
                0xbe, 0xbf,
            ]
        );
    }

    #[test]
    fn is_not_symmetric() {
        let a = [0x11u8; 16];
        let mut b = [0x22u8; 16];
        b[0] = 0x33;
        assert_ne!(derive_session_key(&a, &b), derive_session_key(&b, &a));
    }
}
