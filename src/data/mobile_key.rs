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

/// Encode a single TLV with private class tag
fn encode_tlv(output: &mut Vec<u8>, tag_number: u8, value: &[u8]) {
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
