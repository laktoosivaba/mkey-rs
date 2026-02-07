use crate::transport::traits::{
    DiscoveredLock, ProtocolFlags, SALTO_MANUFACTURER_ID, SALTO_SERVICE_UUID,
};
use std::collections::HashMap;
use uuid::Uuid;

/// Parse SALTO advertisement data from BLE manufacturer data.
///
/// Returns `Some(DiscoveredLock)` if the manufacturer data matches SALTO format,
/// `None` otherwise.
pub fn parse_salto_advertisement(
    id: String,
    name: Option<String>,
    rssi: Option<i16>,
    manufacturer_data: &HashMap<u16, Vec<u8>>,
) -> Option<DiscoveredLock> {
    let data = manufacturer_data.get(&SALTO_MANUFACTURER_ID)?;

    // Minimum 3 bytes: protocol version, reserved, flags
    if data.len() < 3 {
        return None;
    }

    let protocol_version = data[0];
    // data[1] is reserved
    let flags = ProtocolFlags::from_byte(data[2]);

    Some(DiscoveredLock {
        id,
        name,
        rssi,
        protocol_version,
        flags,
    })
}

/// Check if advertised services contain the SALTO service UUID.
///
/// Some SALTO locks advertise their service UUID but not manufacturer data.
/// This function creates a DiscoveredLock with default protocol values when
/// the SALTO service UUID is found.
pub fn parse_salto_by_service_uuid(
    id: String,
    name: Option<String>,
    rssi: Option<i16>,
    service_uuids: &[Uuid],
) -> Option<DiscoveredLock> {
    if service_uuids.contains(&SALTO_SERVICE_UUID) {
        Some(DiscoveredLock {
            id,
            name,
            rssi,
            // Default values when detected by service UUID only
            protocol_version: 0,
            flags: ProtocolFlags::default(),
        })
    } else {
        None
    }
}
