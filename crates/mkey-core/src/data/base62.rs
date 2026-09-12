const BASE62_CHARS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Encode bytes to Base62 string for key lookup
///
/// Used in OPEN command to encode [8-byte key ID + 2-byte CRC] for key lookup.
/// The SDK uses character set: 0-9A-Za-z (standard Base62)
///
/// The input is one big-endian integer of arbitrary width, so the conversion
/// is long division: divide the whole buffer by 62, keep the remainder as a
/// digit, repeat until nothing is left. A bignum library would do the same
/// thing, and this way the protocol carries no arbitrary-precision arithmetic
/// into a browser for the sake of ten bytes.
pub fn encode_base62(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    if data.iter().all(|&byte| byte == 0) {
        return "0".repeat(data.len() + 1);
    }

    let mut value = data.to_vec();
    // Everything before this is known to be zero and can be skipped.
    let mut start = 0;
    let mut digits = Vec::new();

    while start < value.len() {
        let mut remainder = 0u16;

        for byte in &mut value[start..] {
            let accumulator = (remainder << 8) | u16::from(*byte);
            *byte = (accumulator / 62) as u8;
            remainder = accumulator % 62;
        }

        digits.push(BASE62_CHARS[remainder as usize]);

        while start < value.len() && value[start] == 0 {
            start += 1;
        }
    }

    digits.reverse();
    String::from_utf8(digits).expect("the alphabet is ASCII")
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
