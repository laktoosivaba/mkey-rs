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
