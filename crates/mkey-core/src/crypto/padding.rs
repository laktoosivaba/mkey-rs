/// Apply ISO 7816-4 padding to data
///
/// Always pads to the next 16-byte boundary, even if data is already aligned.
/// Format: `<original_data> 0x80 0x00...0x00`
pub fn apply_padding(data: &[u8]) -> Vec<u8> {
    let mut padded = data.to_vec();
    padded.push(0x80);
    while !padded.len().is_multiple_of(16) {
        padded.push(0x00);
    }
    padded
}

/// Remove ISO 7816-4 padding from data
///
/// Removes trailing zeros and the 0x80 marker byte.
/// Returns an error if the padding is invalid (no 0x80 marker found).
pub fn remove_padding(data: &[u8]) -> Result<Vec<u8>, crate::Error> {
    let mut len = data.len();
    while len > 0 && data[len - 1] == 0x00 {
        len -= 1;
    }
    if len > 0 && data[len - 1] == 0x80 {
        len -= 1;
        Ok(data[..len].to_vec())
    } else {
        Err(crate::Error::InvalidPadding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_becomes_one_full_block() {
        let padded = apply_padding(&[]);
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[0], 0x80);
        assert!(padded[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn aligned_input_gains_a_whole_extra_block() {
        let data = [0xAAu8; 16];
        let padded = apply_padding(&data);
        assert_eq!(padded.len(), 32);
        assert_eq!(&padded[..16], &data);
        assert_eq!(padded[16], 0x80);
        assert!(padded[17..].iter().all(|&b| b == 0));
    }

    #[test]
    fn fifteen_bytes_need_only_the_marker() {
        let data = [0x11u8; 15];
        let padded = apply_padding(&data);
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[15], 0x80);
    }

    #[test]
    fn round_trips_every_length_up_to_three_blocks() {
        for len in 0..48usize {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let padded = apply_padding(&data);
            assert!(padded.len().is_multiple_of(16), "len {len}");
            assert!(padded.len() > data.len(), "len {len}");
            assert_eq!(remove_padding(&padded).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn data_ending_in_0x80_still_round_trips() {
        let data = vec![0x01, 0x80];
        assert_eq!(remove_padding(&apply_padding(&data)).unwrap(), data);
    }

    #[test]
    fn data_ending_in_zeros_still_round_trips() {
        // The trailing zeros of the payload are indistinguishable from padding
        // zeros only until the 0x80 marker is found, which sits after them.
        let data = vec![0x01, 0x00, 0x00];
        assert_eq!(remove_padding(&apply_padding(&data)).unwrap(), data);
    }

    #[test]
    fn missing_marker_is_rejected() {
        assert!(matches!(
            remove_padding(&[0x01, 0x02, 0x03]),
            Err(crate::Error::InvalidPadding)
        ));
        assert!(matches!(
            remove_padding(&[]),
            Err(crate::Error::InvalidPadding)
        ));
        assert!(matches!(
            remove_padding(&[0x00; 16]),
            Err(crate::Error::InvalidPadding)
        ));
    }
}
