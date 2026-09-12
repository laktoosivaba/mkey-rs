//! Recognising a SALTO lock in what the platform saw while scanning.
//!
//! The payload itself is parsed by [`mkey_core::parse_salto_advertisement`];
//! all that is left here is knowing where a platform keeps it.

use crate::traits::{DiscoveredLock, SALTO_SERVICE_UUID};
use mkey_core::{parse_salto_advertisement, ProtocolFlags, SALTO_MANUFACTURER_ID};
use std::collections::HashMap;
use uuid::Uuid;

/// Recognise a lock by its SALTO manufacturer record.
pub fn discover_by_manufacturer_data(
    id: String,
    name: Option<String>,
    rssi: Option<i16>,
    manufacturer_data: &HashMap<u16, Vec<u8>>,
) -> Option<DiscoveredLock> {
    let advertisement = parse_salto_advertisement(manufacturer_data.get(&SALTO_MANUFACTURER_ID)?)?;

    Some(DiscoveredLock {
        id,
        name,
        rssi,
        protocol_version: advertisement.protocol_version,
        flags: advertisement.flags,
    })
}

/// Recognise a lock by the SALTO service UUID alone.
///
/// Some locks advertise the service but no manufacturer record — the one in
/// the field does exactly this. Version `0` means "unknown", which is also
/// what tells the session not to announce the app protocol to it.
pub fn discover_by_service_uuid(
    id: String,
    name: Option<String>,
    rssi: Option<i16>,
    service_uuids: &[Uuid],
) -> Option<DiscoveredLock> {
    if !service_uuids.contains(&SALTO_SERVICE_UUID) {
        return None;
    }

    Some(DiscoveredLock {
        id,
        name,
        rssi,
        protocol_version: 0,
        flags: ProtocolFlags::default(),
    })
}
