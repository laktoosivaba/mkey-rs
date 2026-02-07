mod advertisement;
mod btleplug_impl;
mod traits;

pub use advertisement::parse_salto_advertisement;
pub use btleplug_impl::BtleplugTransport;
pub use traits::{
    BleTransport, ConnectedLock, DiscoveredLock, LockFilter, Notification, ProtocolFlags, Rf3State,
    SALTO_MANUFACTURER_ID, SALTO_NOTIFY_UUID, SALTO_SERVICE_UUID, SALTO_WRITE_UUID,
};
