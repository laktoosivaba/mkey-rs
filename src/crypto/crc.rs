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
