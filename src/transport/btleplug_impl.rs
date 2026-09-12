use crate::transport::advertisement::{parse_salto_advertisement, parse_salto_by_service_uuid};
use crate::transport::traits::{
    BleTransport, ConnectedLock, DiscoveredLock, LockFilter, Notification, SALTO_MANUFACTURER_ID,
    SALTO_NOTIFY_UUID, SALTO_SERVICE_UUID, SALTO_WRITE_UUID,
};
use crate::Error;
use btleplug::api::{
    Central, CentralEvent, CharPropFlags, Characteristic, Manager as _, Peripheral as _,
    ScanFilter, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use futures::stream::StreamExt;
use std::pin::Pin;
use std::time::Duration;

type NotificationStream =
    Pin<Box<dyn futures::Stream<Item = btleplug::api::ValueNotification> + Send>>;

pub struct BtleplugTransport {
    adapter: Adapter,
    peripheral: Option<Peripheral>,
    write_characteristic: Option<Characteristic>,
    notify_characteristic: Option<Characteristic>,
    notification_stream: Option<NotificationStream>,
}

impl BtleplugTransport {
    pub async fn new() -> Result<Self, Error> {
        let manager = Manager::new().await?;
        let adapters = manager.adapters().await?;
        let adapter = adapters
            .into_iter()
            .next()
            .ok_or_else(|| Error::ConnectionFailed("No Bluetooth adapter found".to_string()))?;

        Ok(Self {
            adapter,
            peripheral: None,
            write_characteristic: None,
            notify_characteristic: None,
            notification_stream: None,
        })
    }

    async fn find_characteristic(
        peripheral: &Peripheral,
        uuid: uuid::Uuid,
    ) -> Result<Characteristic, Error> {
        for service in peripheral.services() {
            for characteristic in service.characteristics {
                if characteristic.uuid == uuid {
                    return Ok(characteristic);
                }
            }
        }
        Err(Error::CharacteristicNotFound(uuid.to_string()))
    }

    /// Core connection logic - connects to peripheral and sets up characteristics.
    ///
    /// Deliberately stops at "the link is up and the characteristics are known". Working
    /// out which stack the lock speaks is protocol, not transport, and it lives in the
    /// session layer (`lock.rs::detect_protocol_version`).
    async fn connect_to_peripheral(
        &mut self,
        peripheral: Peripheral,
        info: DiscoveredLock,
    ) -> Result<ConnectedLock, Error> {
        eprintln!("[DEBUG] connect_to_peripheral: connecting...");
        peripheral.connect().await?;

        eprintln!("[DEBUG] connect_to_peripheral: discovering services...");
        peripheral.discover_services().await?;

        // Validate SALTO service exists
        let has_salto_service = peripheral
            .services()
            .iter()
            .any(|s| s.uuid == SALTO_SERVICE_UUID);

        if !has_salto_service {
            eprintln!("[DEBUG] connect_to_peripheral: SALTO service NOT found");
            peripheral.disconnect().await?;
            return Err(Error::ServiceNotFound(SALTO_SERVICE_UUID.to_string()));
        }
        eprintln!("[DEBUG] connect_to_peripheral: SALTO service found");

        // Find characteristics
        let write_char = Self::find_characteristic(&peripheral, SALTO_WRITE_UUID).await?;
        let notify_char = Self::find_characteristic(&peripheral, SALTO_NOTIFY_UUID).await?;
        eprintln!(
            "[DEBUG] connect_to_peripheral: characteristics found (write_props={:?}, notify_props={:?}, notify_descs={})",
            write_char.properties,
            notify_char.properties,
            notify_char.descriptors.len()
        );

        // Store connection state
        self.peripheral = Some(peripheral);
        self.write_characteristic = Some(write_char);
        self.notify_characteristic = Some(notify_char);
        self.notification_stream = None;

        eprintln!("[DEBUG] connect_to_peripheral: complete");
        Ok(ConnectedLock { info })
    }

    /// Try to parse peripheral properties as a SALTO lock.
    fn try_parse_salto_lock(
        peripheral: &Peripheral,
        props: &btleplug::api::PeripheralProperties,
    ) -> Option<DiscoveredLock> {
        let id = peripheral.id().to_string();
        let name = props.local_name.clone();
        let rssi = props.rssi;

        parse_salto_advertisement(id.clone(), name.clone(), rssi, &props.manufacturer_data)
            .or_else(|| parse_salto_by_service_uuid(id, name, rssi, &props.services))
    }
}

impl BleTransport for BtleplugTransport {
    async fn scan(&self, duration: Duration) -> Result<Vec<DiscoveredLock>, Error> {
        self.adapter.start_scan(ScanFilter::default()).await?;
        tokio::time::sleep(duration).await;
        self.adapter.stop_scan().await?;

        let peripherals = self.adapter.peripherals().await?;
        let mut locks = Vec::new();

        for peripheral in peripherals {
            if let Ok(Some(props)) = peripheral.properties().await {
                if let Some(lock) = Self::try_parse_salto_lock(&peripheral, &props) {
                    locks.push(lock);
                }
            }
        }

        Ok(locks)
    }

    async fn scan_and_connect(
        &mut self,
        timeout: Duration,
        filter: Option<LockFilter>,
    ) -> Result<ConnectedLock, Error> {
        eprintln!("[DEBUG] scan_and_connect: starting scan...");
        let mut events = self.adapter.events().await?;
        self.adapter.start_scan(ScanFilter::default()).await?;

        let result = tokio::time::timeout(timeout, async {
            while let Some(event) = events.next().await {
                match event {
                    CentralEvent::DeviceDiscovered(id) | CentralEvent::DeviceUpdated(id) => {
                        if let Ok(peripheral) = self.adapter.peripheral(&id).await {
                            if let Ok(Some(props)) = peripheral.properties().await {
                                eprintln!(
                                    "[DEBUG] device {:?} mfr_keys={:?} salto_mfr={:02X?} svc={:?}",
                                    props.local_name,
                                    props.manufacturer_data.keys().collect::<Vec<_>>(),
                                    props
                                        .manufacturer_data
                                        .get(&SALTO_MANUFACTURER_ID)
                                        .map(|v| v.as_slice())
                                        .unwrap_or(&[]),
                                    props.services
                                );

                                if let Some(info) = Self::try_parse_salto_lock(&peripheral, &props)
                                {
                                    let should_connect =
                                        filter.as_ref().map(|f| f(&info)).unwrap_or(true);

                                    eprintln!(
                                        "[DEBUG] SALTO lock {:?} should_connect={}",
                                        info.name, should_connect
                                    );

                                    if should_connect {
                                        self.adapter.stop_scan().await.ok();
                                        return self.connect_to_peripheral(peripheral, info).await;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(Error::NoLocksFound)
        })
        .await;

        let _ = self.adapter.stop_scan().await;

        match result {
            Ok(inner) => inner,
            Err(_) => Err(Error::Timeout(timeout.as_millis() as u64)),
        }
    }

    async fn connect_by_id(
        &mut self,
        lock_id: &str,
        timeout: Duration,
    ) -> Result<ConnectedLock, Error> {
        eprintln!("[DEBUG] connect_by_id: looking for {}", lock_id);
        let mut events = self.adapter.events().await?;
        self.adapter.start_scan(ScanFilter::default()).await?;

        let result = tokio::time::timeout(timeout, async {
            while let Some(event) = events.next().await {
                match event {
                    CentralEvent::DeviceDiscovered(id) | CentralEvent::DeviceUpdated(id) => {
                        if let Ok(peripheral) = self.adapter.peripheral(&id).await {
                            if peripheral.id().to_string() == lock_id {
                                if let Ok(Some(props)) = peripheral.properties().await {
                                    if let Some(info) =
                                        Self::try_parse_salto_lock(&peripheral, &props)
                                    {
                                        self.adapter.stop_scan().await.ok();
                                        return self.connect_to_peripheral(peripheral, info).await;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(Error::NoLocksFound)
        })
        .await;

        let _ = self.adapter.stop_scan().await;

        match result {
            Ok(inner) => inner,
            Err(_) => Err(Error::Timeout(timeout.as_millis() as u64)),
        }
    }

    async fn disconnect(&mut self) -> Result<(), Error> {
        if let Some(peripheral) = self.peripheral.take() {
            if peripheral.is_connected().await? {
                peripheral.disconnect().await?;
            }
        }
        self.write_characteristic = None;
        self.notify_characteristic = None;
        self.notification_stream = None;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.peripheral.is_some()
    }

    async fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        let peripheral = self.peripheral.as_ref().ok_or(Error::Disconnected)?;
        let characteristic = self
            .write_characteristic
            .as_ref()
            .ok_or(Error::Disconnected)?;

        eprintln!("[DEBUG] BLE write ({} bytes): {:02X?}", data.len(), data);
        let write_type = if characteristic.properties.contains(CharPropFlags::WRITE) {
            WriteType::WithResponse
        } else {
            WriteType::WithoutResponse
        };
        eprintln!("[DEBUG] BLE write type: {:?}", write_type);
        peripheral.write(characteristic, data, write_type).await?;
        eprintln!("[DEBUG] BLE write complete");
        Ok(())
    }

    async fn receive(&mut self) -> Result<Option<Notification>, Error> {
        let stream = self
            .notification_stream
            .as_mut()
            .ok_or(Error::Disconnected)?;

        eprintln!("[DEBUG] BLE receive: waiting for notification...");
        match stream.next().await {
            Some(notification) => {
                eprintln!(
                    "[DEBUG] BLE receive: got {} bytes: {:02X?}",
                    notification.value.len(),
                    notification.value
                );
                Ok(Some(Notification {
                    data: notification.value,
                }))
            }
            None => {
                eprintln!("[DEBUG] BLE receive: stream ended");
                Ok(None)
            }
        }
    }

    async fn subscribe(&mut self) -> Result<(), Error> {
        if self.notification_stream.is_some() {
            return Ok(());
        }

        let peripheral = self.peripheral.as_ref().ok_or(Error::Disconnected)?;
        let notify_char = self
            .notify_characteristic
            .as_ref()
            .ok_or(Error::Disconnected)?;

        // Create the stream first so we don't miss the first notification after CCCD is enabled.
        let stream = peripheral.notifications().await?;
        peripheral.subscribe(notify_char).await?;
        eprintln!("[DEBUG] subscribe: subscribed to notifications");

        self.notification_stream = Some(stream);
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    }

    async fn read_notify_value(&mut self) -> Result<Vec<u8>, Error> {
        let peripheral = self.peripheral.as_ref().ok_or(Error::Disconnected)?;
        let characteristic = self
            .notify_characteristic
            .as_ref()
            .ok_or(Error::Disconnected)?;
        Ok(peripheral.read(characteristic).await?)
    }

    fn notify_readable(&self) -> bool {
        self.notify_characteristic
            .as_ref()
            .is_some_and(|c| c.properties.contains(CharPropFlags::READ))
    }
}
