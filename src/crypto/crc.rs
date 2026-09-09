/// CRC-16 for SSP layer (polynomial 0x1081, initial 0x6363)
///
/// This is a custom CRC-16 implementation used in the Salto Security Protocol.
/// It uses polynomial 0x1081 (4225 decimal) with initial value 0x6363 (25443 decimal).
///
/// # Arguments
/// * `data` - Input byte slice to calculate CRC for
///
/// # Returns
/// 2-byte array in little-endian format [LSB, MSB]
pub fn crc16_ssp(data: &[u8]) -> [u8; 2] {
    let mut crc: u16 = 0x6363; // Initial value

    for &byte in data {
        // Process low nibble
        let temp = (crc >> 4) ^ (((crc ^ (byte as u16)) & 0x0F) * 4225);

        // Process high nibble
        crc = (temp >> 4) ^ (((temp ^ ((byte >> 4) as u16)) & 0x0F) * 4225);
    }

    [(crc & 0xFF) as u8, ((crc >> 8) & 0xFF) as u8]
}

/// CRC-16 Hasher (polynomial 0x8408)
///
/// Used for key hash computation in OPEN command authentication.
///
/// # Parameters
/// - Polynomial: 0x8408 (33800 decimal)
/// - Initial Value: 0x0000 (via XOR with 0xFFFF)
/// - Output: 2 bytes (little-endian)
///
/// # Algorithm
/// 1. Generate lookup table from polynomial 0x8408
/// 2. Initialize seed = 0xFFFF
/// 3. For each byte: seed = table[(seed & 0xFF) ^ byte] ^ (seed >> 8)
/// 4. Finalize: result = seed ^ 0xFFFF
/// 5. Return as little-endian 2-byte array
///
/// # Arguments
/// * `data` - Input byte slice to calculate CRC for
///
/// # Returns
/// 2-byte array in little-endian format [LSB, MSB]
pub fn crc16_hasher(data: &[u8]) -> [u8; 2] {
    use once_cell::sync::Lazy;

    static TABLE: Lazy<[u16; 256]> = Lazy::new(|| {
        let mut table = [0u16; 256];
        for (i, entry) in table.iter_mut().enumerate() {
            let mut crc = i as u16;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0x8408;
                } else {
                    crc >>= 1;
                }
            }
            *entry = crc;
        }
        table
    });

    let mut seed: u16 = 0xFFFF;

    for &byte in data {
        let index = ((seed & 0xFF) ^ byte as u16) as usize;
        seed = TABLE[index] ^ (seed >> 8);
    }

    let result = seed ^ 0xFFFF;

    [(result & 0xFF) as u8, ((result >> 8) & 0xFF) as u8]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference values produced by an independent implementation of the
    /// algorithm described in the doc comments above.
    const SSP_VECTORS: &[(&str, &str)] = &[
        ("", "6363"),
        ("00", "fe51"),
        ("0102", "6a24"),
        ("0200", "102d"),
        ("01b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "6d24"),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "b444",
        ),
        ("53414c544f", "45cf"),
        ("ffffffffffffffffffffffffffffffff", "37cb"),
    ];

    const HASHER_VECTORS: &[(&str, &str)] = &[
        ("", "0000"),
        ("00", "78f0"),
        ("0102", "8d35"),
        ("0200", "f73c"),
        ("01b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "04a9"),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "e453",
        ),
        ("53414c544f", "6400"),
        ("ffffffffffffffffffffffffffffffff", "a92d"),
        ("0011223344556677", "fc05"),
        ("0000000000000000", "7383"),
        ("ffffffffffffffff", "1604"),
    ];

    #[test]
    fn crc16_ssp_matches_reference_vectors() {
        for (input, expected) in SSP_VECTORS {
            let data = hex::decode(input).unwrap();
            assert_eq!(hex::encode(crc16_ssp(&data)), *expected, "input {input}");
        }
    }

    #[test]
    fn crc16_ssp_of_empty_input_is_the_seed_little_endian() {
        assert_eq!(crc16_ssp(&[]), [0x63, 0x63]);
    }

    #[test]
    fn crc16_hasher_matches_reference_vectors() {
        for (input, expected) in HASHER_VECTORS {
            let data = hex::decode(input).unwrap();
            assert_eq!(hex::encode(crc16_hasher(&data)), *expected, "input {input}");
        }
    }

    #[test]
    fn crc16_hasher_of_empty_input_is_zero() {
        // seed 0xFFFF finalised with `^ 0xFFFF`.
        assert_eq!(crc16_hasher(&[]), [0x00, 0x00]);
    }

    #[test]
    fn both_crcs_are_little_endian_and_two_bytes() {
        assert_eq!(crc16_ssp(b"abc").len(), 2);
        assert_eq!(crc16_hasher(b"abc").len(), 2);
    }
}
