const BASE62_CHARS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Encode bytes to Base62 string for key lookup
///
/// Used in OPEN command to encode [8-byte key ID + 2-byte CRC] for key lookup.
/// The SDK uses character set: 0-9A-Za-z (standard Base62)
pub fn encode_base62(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let mut num = num_bigint::BigUint::from(0u8);
    for &byte in data {
        num = (num << 8) | num_bigint::BigUint::from(byte);
    }

    if num == num_bigint::BigUint::from(0u8) {
        return "0".repeat(data.len() + 1);
    }

    let mut result = Vec::new();
    let base = num_bigint::BigUint::from(62u8);
    let mut n = num;

    while n > num_bigint::BigUint::from(0u8) {
        let remainder = &n % &base;
        let idx = remainder.to_u64_digits();
        let digit = if idx.is_empty() { 0 } else { idx[0] as usize };
        result.push(BASE62_CHARS[digit]);
        n /= &base;
    }

    result.reverse();
    String::from_utf8(result).unwrap()
}
