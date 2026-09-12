use crate::Error;
use std::collections::HashMap;

/// Permission flags for general-purpose tags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions(u8);

impl Permissions {
    pub const WRITE_WITHOUT_SECURITY: Self = Permissions(0x20);
    pub const READ_WITHOUT_SECURITY: Self = Permissions(0x10);
    pub const WRITABLE: Self = Permissions(0x08);
    pub const READABLE: Self = Permissions(0x04);
    pub const REMOVE_IF_ABSENT: Self = Permissions(0x02);
    pub const OVERWRITE_IF_PRESENT: Self = Permissions(0x01);

    pub fn new(flags: u8) -> Self {
        Self(flags)
    }

    pub fn flags(&self) -> u8 {
        self.0
    }

    pub fn contains(&self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub fn is_readable(&self) -> bool {
        self.contains(Self::READABLE)
    }

    pub fn is_writable(&self) -> bool {
        self.contains(Self::WRITABLE)
    }

    pub fn read_without_security(&self) -> bool {
        self.contains(Self::READ_WITHOUT_SECURITY)
    }

    pub fn write_without_security(&self) -> bool {
        self.contains(Self::WRITE_WITHOUT_SECURITY)
    }

    pub fn remove_if_absent(&self) -> bool {
        self.contains(Self::REMOVE_IF_ABSENT)
    }

    pub fn overwrite_if_present(&self) -> bool {
        self.contains(Self::OVERWRITE_IF_PRESENT)
    }
}

/// A general-purpose tag with permissions
#[derive(Debug, Clone)]
pub struct GeneralPurposeTag {
    pub tag_id: u8,
    pub permissions: Permissions,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TagData {
    pub permissions: Permissions,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MobileKey {
    pub tag_0: Vec<u8>,
    pub tag_1: Vec<u8>,
    pub kn_key: [u8; 16],
    pub tags: HashMap<u8, GeneralPurposeTag>,
}

const TAG_SYSTEM_DEPRECATED_AUDIT: u8 = 0x0A;
const TAG_SYSTEM_AUDIT: u8 = 0x0B;
const TAG_SYSTEM_OPENING_MODE: u8 = 0x10;

impl MobileKey {
    /// Parse MobileKey from hex string
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex)?;
        Self::from_bytes(&bytes)
    }

    /// Parse MobileKey from raw bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        use iso7816_tlv::ber::{Tlv, Value};

        let tlvs = Tlv::parse_all(data);

        let mut tag_0 = None;
        let mut tag_1 = None;
        let mut kn_key = None;
        let mut tags = HashMap::new();

        for tlv in tlvs {
            let tag_bytes = tlv.tag().to_bytes();
            let tag_number = tag_bytes[0] & 0x1F;

            let value_bytes = match tlv.value() {
                Value::Primitive(bytes) => bytes,
                Value::Constructed(_) => continue,
            };

            match tag_number {
                0x00 => tag_0 = Some(value_bytes.clone()),
                0x01 => tag_1 = Some(value_bytes.clone()),
                0x02 => {
                    if value_bytes.len() != 16 {
                        return Err(Error::InvalidKeyLength(value_bytes.len()));
                    }
                    let mut key = [0u8; 16];
                    key.copy_from_slice(value_bytes);
                    kn_key = Some(key);
                }
                0x03 => {
                    if value_bytes.is_empty() {
                        continue;
                    }
                    let permissions = Permissions::new(value_bytes[0]);
                    let inner_tlvs = Tlv::parse_all(&value_bytes[1..]);
                    for inner in inner_tlvs {
                        let inner_tag_bytes = inner.tag().to_bytes();
                        let inner_tag = inner_tag_bytes[0] & 0x1F;
                        if let Value::Primitive(inner_value) = inner.value() {
                            tags.insert(
                                inner_tag,
                                GeneralPurposeTag {
                                    tag_id: inner_tag,
                                    permissions,
                                    value: inner_value.clone(),
                                },
                            );
                        }
                    }
                }
                0x0A | 0x0B | 0x10 => continue,
                _ => continue,
            }
        }

        // System tags (0x0A, 0x0B, 0x10) are excluded from the on-wire MobileKey TLV.
        // The Java SDK materializes them in-memory so the lock can write audit/result data.
        tags.entry(TAG_SYSTEM_DEPRECATED_AUDIT)
            .or_insert(GeneralPurposeTag {
                tag_id: TAG_SYSTEM_DEPRECATED_AUDIT,
                permissions: Permissions::new(
                    Permissions::WRITABLE.0 | Permissions::WRITE_WITHOUT_SECURITY.0,
                ),
                value: Vec::new(),
            });
        tags.entry(TAG_SYSTEM_AUDIT).or_insert(GeneralPurposeTag {
            tag_id: TAG_SYSTEM_AUDIT,
            permissions: Permissions::new(
                Permissions::WRITABLE.0 | Permissions::WRITE_WITHOUT_SECURITY.0,
            ),
            value: Vec::new(),
        });
        // Opening mode (0x10) is set by higher layers when needed; do not default-insert it.

        Ok(MobileKey {
            tag_0: tag_0.ok_or_else(|| Error::TlvError("missing tag 0".into()))?,
            tag_1: tag_1.ok_or_else(|| Error::TlvError("missing tag 1".into()))?,
            kn_key: kn_key.ok_or_else(|| Error::TlvError("missing kN key".into()))?,
            tags,
        })
    }

    /// Encode MobileKey back to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Encode tag 0x00
        encode_tlv(&mut result, 0x00, &self.tag_0);

        // Encode tag 0x01
        encode_tlv(&mut result, 0x01, &self.tag_1);

        // Encode tag 0x02 (kN key)
        encode_tlv(&mut result, 0x02, &self.kn_key);

        // Encode general-purpose tags in 0x03 containers
        for tag in self.tags.values() {
            if matches!(
                tag.tag_id,
                TAG_SYSTEM_DEPRECATED_AUDIT | TAG_SYSTEM_AUDIT | TAG_SYSTEM_OPENING_MODE
            ) {
                continue;
            }
            let mut container_value = Vec::new();
            container_value.push(tag.permissions.flags());

            // Encode inner TLV
            encode_tlv(&mut container_value, tag.tag_id, &tag.value);

            // Encode container
            encode_tlv(&mut result, 0x03, &container_value);
        }

        result
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn new(kn_key: [u8; 16]) -> Self {
        Self {
            tag_0: Vec::new(),
            tag_1: Vec::new(),
            kn_key,
            tags: HashMap::new(),
        }
    }

    pub fn get_tag(&self, tag_id: u8) -> Option<TagData> {
        if tag_id <= 0x01 {
            let data = match tag_id {
                0x00 => &self.tag_0,
                0x01 => &self.tag_1,
                _ => return None,
            };
            return Some(TagData {
                permissions: Permissions::new(Permissions::READABLE.0),
                data: data.clone(),
            });
        }

        if tag_id == 0x02 {
            return Some(TagData {
                permissions: Permissions::new(Permissions::READABLE.0),
                data: self.kn_key.to_vec(),
            });
        }

        self.tags.get(&tag_id).map(|tag| TagData {
            permissions: tag.permissions,
            data: tag.value.clone(),
        })
    }

    pub fn set_tag_data(&mut self, tag_id: u8, data: Vec<u8>) {
        if let Some(tag) = self.tags.get_mut(&tag_id) {
            tag.value = data;
        } else {
            self.tags.insert(
                tag_id,
                GeneralPurposeTag {
                    tag_id,
                    permissions: Permissions::new(
                        Permissions::READABLE.0 | Permissions::WRITABLE.0,
                    ),
                    value: data,
                },
            );
        }
    }
}

/// Encode a single BER-TLV with a private-class primitive tag.
///
/// Tag byte is `0xC0 | (tag_number & 0x1F)`; the length uses the short form
/// below 128 and the `0x81`/`0x82`/`0x83` long forms above it.
pub fn encode_tlv(output: &mut Vec<u8>, tag_number: u8, value: &[u8]) {
    // Tag byte: Private class (0xC0) | tag number
    output.push(0xC0 | (tag_number & 0x1F));

    // Length encoding
    let len = value.len();
    if len < 128 {
        // Short form
        output.push(len as u8);
    } else if len < 256 {
        // Long form: 1 byte
        output.push(0x81);
        output.push(len as u8);
    } else if len < 65536 {
        // Long form: 2 bytes
        output.push(0x82);
        output.push((len >> 8) as u8);
        output.push(len as u8);
    } else {
        // Long form: 3 bytes (supports up to 16MB)
        output.push(0x83);
        output.push((len >> 16) as u8);
        output.push((len >> 8) as u8);
        output.push(len as u8);
    }

    // Value
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_tlv(&mut out, tag, value);
        out
    }

    fn gp_container(tag_id: u8, permissions: u8, value: &[u8]) -> Vec<u8> {
        let mut inner = vec![permissions];
        encode_tlv(&mut inner, tag_id, value);
        tlv(0x03, &inner)
    }

    const KN: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    fn minimal_key_bytes() -> Vec<u8> {
        [
            tlv(0x00, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]),
            tlv(0x01, &[0xAA; 40]),
            tlv(0x02, &KN),
        ]
        .concat()
    }

    // -- TLV encoding ------------------------------------------------------

    #[test]
    fn tag_byte_is_private_class_primitive() {
        assert_eq!(tlv(0x00, &[])[0], 0xC0);
        assert_eq!(tlv(0x01, &[])[0], 0xC1);
        assert_eq!(tlv(0x0B, &[])[0], 0xCB);
        // Only the low five bits of the tag number are used.
        assert_eq!(tlv(0x25, &[])[0], 0xC5);
    }

    #[test]
    fn short_form_length_below_128() {
        assert_eq!(tlv(0x00, &[]), vec![0xC0, 0x00]);
        assert_eq!(tlv(0x00, &[0xFF]), vec![0xC0, 0x01, 0xFF]);
        let encoded = tlv(0x00, &[0u8; 127]);
        assert_eq!(&encoded[..2], &[0xC0, 0x7F]);
        assert_eq!(encoded.len(), 2 + 127);
    }

    #[test]
    fn long_form_one_length_byte_from_128_to_255() {
        let encoded = tlv(0x01, &[0u8; 128]);
        assert_eq!(&encoded[..3], &[0xC1, 0x81, 0x80]);
        assert_eq!(encoded.len(), 3 + 128);

        let encoded = tlv(0x01, &[0u8; 255]);
        assert_eq!(&encoded[..3], &[0xC1, 0x81, 0xFF]);
        assert_eq!(encoded.len(), 3 + 255);
    }

    #[test]
    fn long_form_two_length_bytes_from_256() {
        let encoded = tlv(0x01, &[0u8; 256]);
        assert_eq!(&encoded[..4], &[0xC1, 0x82, 0x01, 0x00]);
        assert_eq!(encoded.len(), 4 + 256);

        let encoded = tlv(0x01, &[0u8; 65_535]);
        assert_eq!(&encoded[..4], &[0xC1, 0x82, 0xFF, 0xFF]);
        assert_eq!(encoded.len(), 4 + 65_535);
    }

    #[test]
    fn long_form_three_length_bytes_from_65536() {
        let encoded = tlv(0x01, &[0u8; 65_536]);
        assert_eq!(&encoded[..5], &[0xC1, 0x83, 0x01, 0x00, 0x00]);
        assert_eq!(encoded.len(), 5 + 65_536);
    }

    // -- MobileKey parsing -------------------------------------------------

    #[test]
    fn parses_the_three_mandatory_tags() {
        let key = MobileKey::from_bytes(&minimal_key_bytes()).unwrap();
        assert_eq!(
            key.tag_0,
            vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        );
        assert_eq!(key.tag_1, vec![0xAA; 40]);
        assert_eq!(key.kn_key, KN);
    }

    #[test]
    fn materialises_the_system_audit_tags_but_not_the_opening_mode_tag() {
        let key = MobileKey::from_bytes(&minimal_key_bytes()).unwrap();
        let audit = key.tags.get(&0x0B).expect("tag 0x0B is materialised");
        assert_eq!(audit.permissions.flags(), 0x28); // WRITABLE | WRITE_WITHOUT_SECURITY
        assert!(audit.value.is_empty());
        assert_eq!(
            key.tags.get(&0x0A).unwrap().permissions.flags(),
            0x28,
            "the deprecated audit tag is materialised too"
        );
        assert!(
            !key.tags.contains_key(&0x10),
            "the opening-mode tag is only inserted by higher layers"
        );
    }

    #[test]
    fn general_purpose_containers_carry_one_permission_byte() {
        let bytes = [
            minimal_key_bytes(),
            gp_container(0x05, 0x0C, &[1, 2, 3, 4]),
            gp_container(0x06, 0x14, &[9]),
        ]
        .concat();
        let key = MobileKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.tags[&0x05].permissions.flags(), 0x0C);
        assert_eq!(key.tags[&0x05].value, vec![1, 2, 3, 4]);
        assert_eq!(key.tags[&0x06].permissions.flags(), 0x14);
        assert_eq!(key.tags[&0x06].value, vec![9]);
    }

    #[test]
    fn long_values_survive_a_parse_round_trip() {
        for len in [127usize, 128, 255, 256, 300] {
            let value: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let bytes = [
                tlv(0x00, &[0x01; 8]),
                tlv(0x01, &value),
                tlv(0x02, &KN),
                gp_container(0x05, 0x0C, &value),
            ]
            .concat();
            let key = MobileKey::from_bytes(&bytes).unwrap();
            assert_eq!(key.tag_1, value, "tag1 with {len} bytes");
            assert_eq!(key.tags[&0x05].value, value, "tag 0x05 with {len} bytes");
        }
    }

    #[test]
    fn an_empty_container_is_skipped() {
        let bytes = [minimal_key_bytes(), tlv(0x03, &[])].concat();
        let key = MobileKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.tags.len(), 2, "only the two materialised system tags");
    }

    #[test]
    fn top_level_system_tags_are_ignored() {
        let bytes = [
            minimal_key_bytes(),
            tlv(0x0A, &[1]),
            tlv(0x0B, &[2]),
            tlv(0x10, &[3]),
        ]
        .concat();
        let key = MobileKey::from_bytes(&bytes).unwrap();
        assert!(key.tags[&0x0A].value.is_empty());
        assert!(key.tags[&0x0B].value.is_empty());
        assert!(!key.tags.contains_key(&0x10));
    }

    #[test]
    fn missing_mandatory_tags_are_rejected() {
        let cases = [
            (
                [tlv(0x01, &[0xAA; 4]), tlv(0x02, &KN)].concat(),
                "missing tag 0",
            ),
            (
                [tlv(0x00, &[0x01; 8]), tlv(0x02, &KN)].concat(),
                "missing tag 1",
            ),
            (
                [tlv(0x00, &[0x01; 8]), tlv(0x01, &[0xAA; 4])].concat(),
                "missing kN key",
            ),
        ];
        for (bytes, expected) in cases {
            match MobileKey::from_bytes(&bytes) {
                Err(Error::TlvError(message)) => assert_eq!(message, expected),
                other => panic!("expected {expected}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_kn_key_that_is_not_sixteen_bytes_is_rejected() {
        for len in [0usize, 8, 15, 17, 32] {
            let bytes = [
                tlv(0x00, &[0x01; 8]),
                tlv(0x01, &[0xAA; 4]),
                tlv(0x02, &vec![0u8; len]),
            ]
            .concat();
            assert!(
                matches!(MobileKey::from_bytes(&bytes), Err(Error::InvalidKeyLength(n)) if n == len),
                "kN of {len} bytes should be rejected"
            );
        }
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let full = minimal_key_bytes();
        for cut in 1..full.len() {
            let _ = MobileKey::from_bytes(&full[..cut]);
        }
    }

    // -- Accessors ---------------------------------------------------------

    #[test]
    fn legacy_tags_are_read_only_views_onto_the_fixed_fields() {
        let key = MobileKey::from_bytes(&minimal_key_bytes()).unwrap();
        for (id, expected) in [
            (0x00u8, key.tag_0.clone()),
            (0x01, key.tag_1.clone()),
            (0x02, key.kn_key.to_vec()),
        ] {
            let tag = key.get_tag(id).unwrap();
            assert_eq!(tag.data, expected);
            assert_eq!(tag.permissions.flags(), Permissions::READABLE.flags());
        }
        assert!(key.get_tag(0x42).is_none());
    }

    #[test]
    fn set_tag_data_keeps_existing_permissions_and_defaults_to_read_write() {
        let bytes = [minimal_key_bytes(), gp_container(0x05, 0x14, &[1])].concat();
        let mut key = MobileKey::from_bytes(&bytes).unwrap();

        key.set_tag_data(0x05, vec![7, 7]);
        assert_eq!(key.tags[&0x05].permissions.flags(), 0x14, "unchanged");
        assert_eq!(key.tags[&0x05].value, vec![7, 7]);

        key.set_tag_data(0x09, vec![9]);
        assert_eq!(
            key.tags[&0x09].permissions.flags(),
            Permissions::READABLE.flags() | Permissions::WRITABLE.flags()
        );
    }

    #[test]
    fn to_bytes_round_trips_and_drops_the_system_tags() {
        let bytes = [
            minimal_key_bytes(),
            gp_container(0x05, 0x0C, &[1, 2, 3, 4]),
            gp_container(0x06, 0x14, &[9]),
        ]
        .concat();
        let key = MobileKey::from_bytes(&bytes).unwrap();
        let reparsed = MobileKey::from_bytes(&key.to_bytes()).unwrap();

        assert_eq!(reparsed.tag_0, key.tag_0);
        assert_eq!(reparsed.tag_1, key.tag_1);
        assert_eq!(reparsed.kn_key, key.kn_key);
        for id in [0x05u8, 0x06] {
            assert_eq!(reparsed.tags[&id].value, key.tags[&id].value);
            assert_eq!(reparsed.tags[&id].permissions, key.tags[&id].permissions);
        }
        // 0x0A / 0x0B are re-materialised rather than serialised.
        assert!(!key.to_hex().contains("ca00"));
    }

    #[test]
    fn permissions_flags_match_the_documented_bit_values() {
        assert_eq!(Permissions::WRITE_WITHOUT_SECURITY.flags(), 0x20);
        assert_eq!(Permissions::READ_WITHOUT_SECURITY.flags(), 0x10);
        assert_eq!(Permissions::WRITABLE.flags(), 0x08);
        assert_eq!(Permissions::READABLE.flags(), 0x04);
        assert_eq!(Permissions::REMOVE_IF_ABSENT.flags(), 0x02);
        assert_eq!(Permissions::OVERWRITE_IF_PRESENT.flags(), 0x01);

        // `contains` tests for *any* overlapping bit, not a subset.
        let perms = Permissions::new(0x0C);
        assert!(perms.is_readable() && perms.is_writable());
        assert!(!perms.read_without_security());
        assert!(!perms.write_without_security());
    }
}
