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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_an_empty_string() {
        assert_eq!(encode_base62(&[]), "");
    }

    #[test]
    fn zero_value_yields_len_plus_one_zeros() {
        // Quirk of the original implementation: a numerically zero input is not
        // encoded as "0" but as `len + 1` zero characters.
        assert_eq!(encode_base62(&[0x00]), "00");
        assert_eq!(encode_base62(&[0x00, 0x00]), "000");
        assert_eq!(encode_base62(&[0x00; 10]), "00000000000");
    }

    #[test]
    fn alphabet_is_digits_then_lowercase_then_uppercase() {
        assert_eq!(encode_base62(&[0x01]), "1");
        assert_eq!(encode_base62(&[0x0a]), "a");
        assert_eq!(encode_base62(&[0x23]), "z"); // 35 -> last lowercase
        assert_eq!(encode_base62(&[0x24]), "A"); // 36 -> first uppercase
        assert_eq!(encode_base62(&[0x3d]), "Z"); // 61 -> last uppercase
                                                 // 255 = 4 * 62 + 7
        assert_eq!(encode_base62(&[0xff]), "47");
    }

    #[test]
    fn treats_the_input_as_a_big_endian_integer() {
        assert_eq!(
            encode_base62(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]),
            "m5rX98TTp"
        );
        // Leading zero bytes do not survive: the encoding is numeric, not
        // positional, so identifiers are not fixed width.
        assert_eq!(encode_base62(&[0x00, 0x01]), encode_base62(&[0x01]));
    }
}
