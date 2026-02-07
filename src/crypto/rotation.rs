/// Rotate byte array right by 1 byte position (last byte moves to front)
pub fn rotate_right(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(data.len());
    result.push(*data.last().unwrap());
    result.extend_from_slice(&data[..data.len() - 1]);
    result
}
