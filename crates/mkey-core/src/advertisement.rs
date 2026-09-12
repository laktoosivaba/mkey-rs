//! What a SALTO lock says about itself before anyone connects.
//!
//! Only the payload is parsed here. Finding that payload — digging it out of a
//! manufacturer-data map, or falling back to the service UUID — is the
//! platform's job and lives in the transport.

/// Company identifier SALTO uses in its BLE manufacturer record.
pub const SALTO_MANUFACTURER_ID: u16 = 0x0199;

/// A parsed SALTO manufacturer record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaltoAdvertisement {
    /// Major protocol version: 1 = v0100, 2 = v0200.
    pub protocol_version: u8,
    /// Proximity, messages and RF3 state.
    pub flags: ProtocolFlags,
}

/// Parse a SALTO manufacturer record: version, one reserved byte, flags.
///
/// Returns `None` when the record is too short to be one.
pub fn parse_salto_advertisement(data: &[u8]) -> Option<SaltoAdvertisement> {
    if data.len() < 3 {
        return None;
    }

    Some(SaltoAdvertisement {
        protocol_version: data[0],
        flags: ProtocolFlags::from_byte(data[2]),
    })
}

/// Protocol flags parsed from SALTO advertisement data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProtocolFlags {
    /// Proximity mode: false = NEAR, true = REMOTE
    pub remote: bool,
    /// Messages available: false = NO_MESSAGES, true = WITH_MESSAGES
    pub has_messages: bool,
    /// RF3 state
    pub rf3_state: Rf3State,
}

impl ProtocolFlags {
    /// Parse protocol flags from the advertisement byte.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            remote: (byte & 0x01) != 0,
            has_messages: (byte & 0x04) != 0,
            rf3_state: Rf3State::from_bits((byte >> 4) & 0x03),
        }
    }
}

/// RF3 state from advertisement flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Rf3State {
    #[default]
    Off = 0,
    Ini = 1,
    Link = 2,
    Lost = 3,
}

impl Rf3State {
    fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Self::Off,
            1 => Self::Ini,
            2 => Self::Link,
            3 => Self::Lost,
            _ => Self::Off,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_shorter_than_three_bytes_is_not_one() {
        assert_eq!(parse_salto_advertisement(&[]), None);
        assert_eq!(parse_salto_advertisement(&[0x02, 0x00]), None);
    }

    #[test]
    fn the_version_is_the_first_byte_and_the_flags_the_third() {
        let advertisement = parse_salto_advertisement(&[0x02, 0xFF, 0x25]).expect("parsed");

        assert_eq!(advertisement.protocol_version, 2);
        assert!(advertisement.flags.remote);
        assert!(advertisement.flags.has_messages);
        assert_eq!(advertisement.flags.rf3_state, Rf3State::Link);
    }

    #[test]
    fn trailing_bytes_are_ignored() {
        assert_eq!(
            parse_salto_advertisement(&[0x01, 0x00, 0x00, 0xAA, 0xBB]),
            parse_salto_advertisement(&[0x01, 0x00, 0x00])
        );
    }
}
