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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_stays_empty() {
        assert!(rotate_right(&[]).is_empty());
    }

    #[test]
    fn single_byte_is_unchanged() {
        assert_eq!(rotate_right(&[0xAB]), vec![0xAB]);
    }

    #[test]
    fn last_byte_moves_to_the_front() {
        assert_eq!(rotate_right(&[1, 2, 3, 4]), vec![4, 1, 2, 3]);
    }

    #[test]
    fn sixteen_rotations_return_the_original() {
        let original: Vec<u8> = (0..16u8).collect();
        let mut value = original.clone();
        for _ in 0..16 {
            value = rotate_right(&value);
        }
        assert_eq!(value, original);
    }
}
