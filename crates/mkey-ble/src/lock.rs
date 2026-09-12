use crate::traits::{BleTransport, ConnectedLock, DiscoveredLock, LockFilter};
#[cfg(feature = "btleplug")]
use crate::BtleplugTransport;
use mkey_core::command::justin::{JustinProtocolManager, JustinState, NoopKeyStore};
use mkey_core::crypto::encrypt_aes_cbc;
use mkey_core::data::mobile_key::{GeneralPurposeTag, MobileKey, Permissions};
use mkey_core::stack::JustinStack0100;
use mkey_core::Error;
use std::time::Duration;

/// Opening mode for the lock operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpeningMode {
    /// Standard mode - normal open/close.
    #[default]
    Standard = 0,
    /// Office mode - toggle office/latch state (door stays unlocked).
    Office = 1,
}

const TAG_OPENING_MODE: u8 = 0x10;

const DEFAULT_SCAN_DURATION: Duration = Duration::from_secs(5);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_START_TIMEOUT: Duration = Duration::from_secs(30);

/// BER-TLV app protocol request: private tag 0, one byte of value `0x01`.
const APP_PROTOCOL_REQUEST: [u8; 3] = [0xC0, 0x01, 0x01];
/// How long the lock is given to answer the protocol info read.
const PROTOCOL_INFO_READ_TIMEOUT: Duration = Duration::from_millis(1000);
const PROTOCOL_INFO_PREFIX: u8 = 0x01;
const PROTOCOL_INFO_LENGTH: usize = 3;
const PROTOCOL_INFO_MAJOR_INDEX: usize = 2;

/// How the session works out which stack the lock speaks, before it subscribes.
///
/// The reference sequence is [`Detection::AppProtocol`]: write the app protocol
/// request, then read the protocol info back off the notify characteristic. The
/// other modes exist because a lock can drop the link during that handshake, and
/// the only way to tell which half it objected to is to leave one out. One real
/// lock does exactly this: it acknowledges the `c0 01 01` write and then kills
/// the link on the following read, and only [`Detection::ReadOnly`] opens it.
///
/// A failed detection is never fatal in any mode — the version simply stays
/// unknown and the v0200 flow runs. Only the lock dropping the link is.
///
/// Mirrors `VersionDetection` in mkey-js (`session/open-lock.ts`), with
/// [`Detection::Auto`] standing in for that port's `detectionForAdvertisement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Detection {
    /// Pick the mode from the advertisement, then run it.
    ///
    /// A lock that advertises a SALTO manufacturer record gets
    /// [`Detection::AppProtocol`]; a lock recognised by its service UUID alone
    /// gets [`Detection::ReadOnly`]. This is the rule mkey-rs has always
    /// followed on hardware, and it is resolved here, in the shell that can see
    /// the advertisement — the session itself only ever sees a concrete mode.
    #[default]
    Auto,
    /// Write the app protocol request, then read the protocol info.
    AppProtocol,
    /// Read the protocol info without announcing the app protocol first.
    ReadOnly,
    /// Ask nothing at all: subscribe straight away, version unknown.
    None,
}

impl Detection {
    /// The mode [`Detection::Auto`] resolves to for a given advertised version.
    ///
    /// `0` means the lock was recognised by its service UUID alone, i.e. it
    /// carried no SALTO manufacturer record.
    pub fn for_advertised_version(advertised_version: u8) -> Self {
        if advertised_version == 0 {
            Self::ReadOnly
        } else {
            Self::AppProtocol
        }
    }

    fn resolve(self, advertised_version: u8) -> Self {
        match self {
            Self::Auto => Self::for_advertised_version(advertised_version),
            concrete => concrete,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    Disconnected,
    Connected,
    Authenticated,
    SessionOpen,
}

impl std::fmt::Display for LockState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockState::Disconnected => write!(f, "DISCONNECTED"),
            LockState::Connected => write!(f, "CONNECTED"),
            LockState::Authenticated => write!(f, "AUTHENTICATED"),
            LockState::SessionOpen => write!(f, "SESSION_OPEN"),
        }
    }
}

/// The phone side of a SALTO session, driven over any [`BleTransport`].
///
/// The transport is a type parameter so the same session logic runs against
/// btleplug on a desktop and against an in-process simulator in the tests.
pub struct SaltoLock<T: BleTransport> {
    transport: T,
    connected_lock: Option<ConnectedLock>,
    stack: Option<JustinStack0100<NoopKeyStore>>,
    mobile_key_v0100: Option<MobileKey>,
    state: LockState,
    detection: Detection,
}

#[cfg(feature = "btleplug")]
impl SaltoLock<BtleplugTransport> {
    /// Open a session over the first available Bluetooth adapter.
    pub async fn new() -> Result<Self, Error> {
        Ok(Self::with_transport(BtleplugTransport::new().await?))
    }
}

impl<T: BleTransport> SaltoLock<T> {
    /// Build a session over an arbitrary transport.
    pub fn with_transport(transport: T) -> Self {
        Self {
            transport,
            connected_lock: None,
            stack: None,
            mobile_key_v0100: None,
            state: LockState::Disconnected,
            detection: Detection::default(),
        }
    }

    /// Choose how the protocol version is detected. Defaults to [`Detection::Auto`].
    pub fn with_detection(mut self, detection: Detection) -> Self {
        self.detection = detection;
        self
    }

    /// Choose how the protocol version is detected, after construction.
    pub fn set_detection(&mut self, detection: Detection) {
        self.detection = detection;
    }

    pub fn state(&self) -> LockState {
        self.state
    }

    /// Scan for SALTO locks without connecting.
    ///
    /// Useful for displaying a list of available locks to the user.
    pub async fn scan(&self, duration: Option<Duration>) -> Result<Vec<DiscoveredLock>, Error> {
        let duration = duration.unwrap_or(DEFAULT_SCAN_DURATION);
        self.transport.scan(duration).await
    }

    /// Scan for a SALTO lock and connect immediately when found.
    ///
    /// This is the optimized single-phase operation. Connects to the first
    /// SALTO lock discovered.
    pub async fn scan_and_connect(
        &mut self,
        timeout: Option<Duration>,
    ) -> Result<&DiscoveredLock, Error> {
        self.scan_and_connect_filtered(timeout, None).await
    }

    /// Scan for a SALTO lock matching the filter and connect immediately.
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait for a lock.
    /// * `filter` - Optional filter function. If provided, only locks for which
    ///   the filter returns `true` will be connected to.
    pub async fn scan_and_connect_filtered(
        &mut self,
        timeout: Option<Duration>,
        filter: Option<LockFilter>,
    ) -> Result<&DiscoveredLock, Error> {
        if self.state != LockState::Disconnected {
            return Err(Error::InvalidState {
                expected: "DISCONNECTED".to_string(),
                actual: self.state.to_string(),
            });
        }

        let timeout = timeout.unwrap_or(DEFAULT_SCAN_DURATION);
        let connected = self.transport.scan_and_connect(timeout, filter).await?;

        self.after_connect(connected).await
    }

    /// Connect to a previously discovered lock by its ID.
    ///
    /// Use this for the "user picks from list" workflow:
    /// 1. Call `scan()` to get a list of locks
    /// 2. Let the user choose a lock
    /// 3. Call `connect_by_id()` with the chosen lock's ID
    pub async fn connect_by_id(
        &mut self,
        lock_id: &str,
        timeout: Option<Duration>,
    ) -> Result<&DiscoveredLock, Error> {
        if self.state != LockState::Disconnected {
            return Err(Error::InvalidState {
                expected: "DISCONNECTED".to_string(),
                actual: self.state.to_string(),
            });
        }

        let timeout = timeout.unwrap_or(DEFAULT_TIMEOUT);
        let connected = self.transport.connect_by_id(lock_id, timeout).await?;

        self.after_connect(connected).await
    }

    /// Record a fresh connection and work out which stack the lock speaks.
    ///
    /// Detection has to happen here, between connecting and subscribing: the
    /// lock starts driving the exchange as soon as notifications are enabled.
    async fn after_connect(&mut self, connected: ConnectedLock) -> Result<&DiscoveredLock, Error> {
        self.connected_lock = Some(connected);
        self.stack = None;
        self.mobile_key_v0100 = None;
        self.state = LockState::Connected;

        let advertised = self.connected_lock.as_ref().unwrap().info.protocol_version;
        if let Some(major) = self.detect_protocol_version(advertised).await {
            self.connected_lock.as_mut().unwrap().info.protocol_version = major;
        }

        Ok(&self.connected_lock.as_ref().unwrap().info)
    }

    /// Ask the lock which protocol stack it speaks, before notifications are enabled.
    ///
    /// Returns `None` when the version could not be established — which is not
    /// an error: the caller keeps whatever the advertisement claimed, and an
    /// unknown version runs the v0200 flow.
    async fn detect_protocol_version(&mut self, advertised_version: u8) -> Option<u8> {
        match self.detection.resolve(advertised_version) {
            Detection::None => {
                eprintln!("[DEBUG] detection: skipped, subscribing straight away");
                return None;
            }
            Detection::AppProtocol => {
                if !self.transport.notify_readable() {
                    eprintln!("[DEBUG] detection: notify characteristic is not readable");
                    return None;
                }

                // Not fatal. At least one lock acknowledges this write and then drops
                // the link on the read that follows; losing the version is better than
                // losing the session, and `Detection::ReadOnly` exists for that lock.
                match self.transport.write(&APP_PROTOCOL_REQUEST).await {
                    Ok(()) => eprintln!(
                        "[DEBUG] detection: wrote app protocol request {:02X?}",
                        APP_PROTOCOL_REQUEST
                    ),
                    Err(e) => eprintln!("[DEBUG] detection: app protocol request failed: {}", e),
                }
            }
            Detection::ReadOnly => {
                if !self.transport.notify_readable() {
                    eprintln!("[DEBUG] detection: notify characteristic is not readable");
                    return None;
                }
            }
            Detection::Auto => unreachable!("resolve() never returns Auto"),
        }

        let read = tokio::time::timeout(
            PROTOCOL_INFO_READ_TIMEOUT,
            self.transport.read_notify_value(),
        )
        .await;

        let info = match read {
            Ok(Ok(info)) => info,
            Ok(Err(e)) => {
                eprintln!("[DEBUG] detection: protocol info read failed: {}", e);
                return None;
            }
            Err(_) => {
                eprintln!(
                    "[DEBUG] detection: no protocol info within {} ms",
                    PROTOCOL_INFO_READ_TIMEOUT.as_millis()
                );
                return None;
            }
        };

        eprintln!(
            "[DEBUG] detection: protocol info ({} bytes): {:02X?}",
            info.len(),
            info
        );

        if info.len() >= PROTOCOL_INFO_LENGTH && info[0] == PROTOCOL_INFO_PREFIX {
            // The version is two little-endian bytes; the Java SDK reverses them
            // before printing, so `major` is the second of the pair.
            let major = info[PROTOCOL_INFO_MAJOR_INDEX];
            eprintln!("[DEBUG] detection: major={} minor={}", major, info[1]);
            return Some(major);
        }

        eprintln!("[DEBUG] detection: protocol info has an unexpected shape");
        None
    }

    /// Get information about the currently connected lock.
    pub fn connected_lock(&self) -> Option<&DiscoveredLock> {
        self.connected_lock.as_ref().map(|c| &c.info)
    }

    pub async fn authenticate(&mut self, mobile_key: MobileKey) -> Result<(), Error> {
        if self.state != LockState::Connected {
            return Err(Error::InvalidState {
                expected: "CONNECTED".to_string(),
                actual: self.state.to_string(),
            });
        }

        let protocol_version = self
            .connected_lock
            .as_ref()
            .map(|c| c.info.protocol_version)
            .unwrap_or(0);

        match protocol_version {
            // BLE v0100: legacy flow (IDD/AT + nonce challenge). SSP is not used.
            1 => {
                self.stack = None;
                self.mobile_key_v0100 = Some(mobile_key);
            }
            // BLE v0200: SSP + Justin command layer.
            0 | 2 => {
                self.mobile_key_v0100 = None;
                let ssp = mkey_core::security::ssp::SecureProtocolManager::new(mobile_key.kn_key);
                let justin = JustinProtocolManager::new_with_key(mobile_key);
                self.stack = Some(JustinStack0100::new(ssp, justin));
            }
            other => {
                return Err(Error::InvalidProtocolVersion(format!(
                    "Unsupported SALTO protocol version: v{}",
                    other
                )));
            }
        }
        self.state = LockState::Authenticated;
        Ok(())
    }

    /// Open the lock in standard mode.
    pub async fn open(&mut self) -> Result<(), Error> {
        self.open_with_mode(OpeningMode::Standard).await
    }

    /// Toggle office mode on the lock (door stays unlocked until toggled again).
    pub async fn open_office(&mut self) -> Result<(), Error> {
        self.open_with_mode(OpeningMode::Office).await
    }

    /// Open the lock with a specific opening mode.
    pub async fn open_with_mode(&mut self, mode: OpeningMode) -> Result<(), Error> {
        if self.state != LockState::Authenticated {
            return Err(Error::InvalidState {
                expected: "AUTHENTICATED".to_string(),
                actual: self.state.to_string(),
            });
        }

        // Set opening mode tag if not standard
        if mode == OpeningMode::Office {
            if let Some(stack) = &mut self.stack {
                if let Some(key) = stack.justin_mut().current_key_mut() {
                    key.tags.insert(
                        TAG_OPENING_MODE,
                        GeneralPurposeTag {
                            tag_id: TAG_OPENING_MODE,
                            permissions: Permissions::new(
                                Permissions::READABLE.flags()
                                    | Permissions::READ_WITHOUT_SECURITY.flags(),
                            ),
                            value: vec![mode as u8],
                        },
                    );
                }
            }
        }

        self.state = LockState::SessionOpen;
        let result = self.open_inner().await;
        if result.is_err() && self.state == LockState::SessionOpen {
            // Restore a stable state so callers can retry or disconnect cleanly.
            self.state = LockState::Authenticated;
        }
        result
    }

    async fn open_inner(&mut self) -> Result<(), Error> {
        let protocol_version = self
            .connected_lock
            .as_ref()
            .map(|c| c.info.protocol_version)
            .unwrap_or(0);

        if protocol_version == 1 {
            return self.open_inner_v0100().await;
        }

        self.open_inner_v0200().await
    }

    async fn open_inner_v0200(&mut self) -> Result<(), Error> {
        self.transport.subscribe().await?;

        // Continue responding to lock-driven Justin commands (now typically encrypted).
        let mut first_packet = true;
        let mut final_op_result: Option<u8> = None;
        loop {
            let timeout = if final_op_result.is_some() {
                // Some locks finish by writing the audit/opresult tag and then stay silent (or
                // disconnect without emitting a final notification). Keep a short grace period
                // after the final opResult so we can still answer an optional CLOSE.
                Duration::from_secs(3)
            } else if first_packet {
                first_packet = false;
                DEFAULT_START_TIMEOUT
            } else {
                DEFAULT_TIMEOUT
            };

            let packet = match self.receive_with_timeout(timeout).await {
                Ok(packet) => packet,
                Err(Error::Timeout(_)) if final_op_result.is_some() => {
                    eprintln!(
                        "[DEBUG] open_inner_v0200: no further packets after final OpResult, finishing"
                    );
                    self.state = LockState::Authenticated;
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let Some(packet) = packet else {
                // Lock disconnected - treat as end of process.
                let _ = self.transport.disconnect().await;
                self.connected_lock = None;
                self.state = LockState::Disconnected;
                return Ok(());
            };

            let stack = self.stack.as_mut().ok_or(Error::InvalidState {
                expected: "Protocol stack initialized".to_string(),
                actual: "No protocol stack".to_string(),
            })?;

            let response = stack.handle_packet(&packet)?;
            self.transport.write(&response).await?;

            // v0200: lock reports the final operation result by writing tag 0x0B (audit).
            // Java SDK reports success/failure after disconnect; we treat a terminal opResult as
            // end-of-session even if the lock doesn't send a CLOSE command.
            if final_op_result.is_none() {
                if let Some(op_result) = stack.justin().last_audit_op_result() {
                    let group = op_result & 3;
                    if group == 2 || group == 3 {
                        final_op_result = Some(op_result);
                    }
                }
            }

            // The lock typically ends the exchange with a Justin CLOSE.
            if stack.justin_state() == JustinState::Ready {
                self.state = LockState::Authenticated;
                return Ok(());
            }
        }
    }

    async fn open_inner_v0100(&mut self) -> Result<(), Error> {
        // BLE v0100 handshake is phone-driven:
        // 0) Enable notifications/indications (CCCD)
        // 1) Write IDD+AT (0x02 + tag_1)
        // 2) Receive random nonce (0x03 + 16 bytes)
        // 3) Write signed random (0x04 + AES-CBC(nonce, key=kN, iv=0xFF..))
        // 4) Receive result (0x05 + opResult [+ optional BER TLVs])
        let (tag_1, kn_key) = {
            let key = self.mobile_key_v0100.as_ref().ok_or(Error::InvalidState {
                expected: "MobileKey loaded for v0100".to_string(),
                actual: "No v0100 MobileKey".to_string(),
            })?;
            (key.tag_1.clone(), key.kn_key)
        };

        self.transport.subscribe().await?;

        // WRITE_IDD_AND_AT
        let mut idd_at = Vec::with_capacity(1 + tag_1.len());
        idd_at.push(0x02);
        idd_at.extend_from_slice(&tag_1);
        eprintln!("[V0100] writing IDD+AT ({} bytes)", idd_at.len());
        // This frame is expected to be delivered atomically by the lock (Android/iOS will use
        // ATT long write or a larger MTU). Splitting it into multiple GATT writes is not valid.
        self.transport.write(&idd_at).await?;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // READ_RANDOM_NONCE
        let nonce_packet = self
            .receive_expected_v0100_packet(0x03, DEFAULT_START_TIMEOUT)
            .await?;
        if nonce_packet.len() < 1 + 16 {
            return Err(Error::InvalidData(format!(
                "v0100 random nonce packet too short: expected 17 bytes, got {}",
                nonce_packet.len()
            )));
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&nonce_packet[1..17]);
        eprintln!("[V0100] received nonce: {:02X?}", nonce);

        // WRITE_SIGNED_RANDOM
        let iv = [0xFFu8; 16];
        let signed = encrypt_aes_cbc(&kn_key, &iv, &nonce);
        if signed.len() != 16 {
            return Err(Error::InvalidData(format!(
                "v0100 signed nonce has unexpected length: {}",
                signed.len()
            )));
        }
        let mut signed_packet = Vec::with_capacity(1 + signed.len());
        signed_packet.push(0x04);
        signed_packet.extend_from_slice(&signed);
        eprintln!(
            "[V0100] writing signed nonce ({} bytes)",
            signed_packet.len()
        );
        self.transport.write(&signed_packet).await?;

        // PROCESS_OK (result)
        let result_packet = self
            .receive_expected_v0100_packet(0x05, DEFAULT_TIMEOUT)
            .await?;
        if result_packet.len() < 2 {
            return Err(Error::InvalidData(format!(
                "v0100 result packet too short: expected >=2 bytes, got {}",
                result_packet.len()
            )));
        }
        let op_result = result_packet[1];
        eprintln!(
            "[LOCK RESULT] OpResult={} ({}) Group={}",
            op_result,
            decode_op_result(op_result),
            decode_op_result_group(op_result)
        );
        if result_packet.len() > 2 {
            eprintln!(
                "[V0100] raw result TLVs ({} bytes): {:02X?}",
                result_packet.len() - 2,
                &result_packet[2..]
            );
        }

        // v0100 flow ends here; the SDK disconnects after PROCESS_OK.
        let _ = self.transport.disconnect().await;
        self.connected_lock = None;
        self.stack = None;
        self.mobile_key_v0100 = None;
        self.state = LockState::Disconnected;
        Ok(())
    }

    async fn receive_expected_v0100_packet(
        &mut self,
        expected_prefix: u8,
        timeout: Duration,
    ) -> Result<Vec<u8>, Error> {
        let start = tokio::time::Instant::now();
        loop {
            let elapsed = start.elapsed();
            let remaining = timeout
                .checked_sub(elapsed)
                .ok_or(Error::Timeout(timeout.as_millis() as u64))?;

            let packet = self.receive_with_timeout(remaining).await?;
            let Some(packet) = packet else {
                let _ = self.transport.disconnect().await;
                self.connected_lock = None;
                self.stack = None;
                self.mobile_key_v0100 = None;
                self.state = LockState::Disconnected;
                return Err(Error::Disconnected);
            };

            if packet.first().copied() == Some(expected_prefix) {
                return Ok(packet);
            }

            eprintln!(
                "[V0100] ignoring unexpected packet while waiting for 0x{:02X}: {:02X?}",
                expected_prefix, packet
            );
        }
    }

    pub async fn read_tag(&mut self, tag_id: u8) -> Result<Vec<u8>, Error> {
        let stack = self.stack.as_ref().ok_or(Error::InvalidState {
            expected: "MobileKey loaded".to_string(),
            actual: "No protocol stack".to_string(),
        })?;

        let key = stack
            .justin()
            .current_key()
            .ok_or(Error::InvalidMobileKey)?;

        match key.get_tag(tag_id) {
            Some(tag) => Ok(tag.data),
            None => Err(Error::KeyNotFound(format!("Tag 0x{:02X}", tag_id))),
        }
    }

    pub async fn write_tag(&mut self, tag_id: u8, data: &[u8]) -> Result<(), Error> {
        let stack = self.stack.as_mut().ok_or(Error::InvalidState {
            expected: "MobileKey loaded".to_string(),
            actual: "No protocol stack".to_string(),
        })?;

        let key = stack
            .justin_mut()
            .current_key_mut()
            .ok_or(Error::InvalidMobileKey)?;

        key.set_tag_data(tag_id, data.to_vec());
        Ok(())
    }

    pub async fn close(&mut self) -> Result<(), Error> {
        // The lock drives the CLOSE command. From the application's point of view,
        // `close()` is an idempotent local transition.
        if self.state == LockState::SessionOpen {
            self.state = LockState::Authenticated;
        }
        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<(), Error> {
        self.transport.disconnect().await?;
        self.connected_lock = None;
        self.stack = None;
        self.mobile_key_v0100 = None;
        self.state = LockState::Disconnected;
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }

    async fn receive_with_timeout(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, Error> {
        let recv = tokio::time::timeout(timeout, async { self.transport.receive().await });

        match recv.await {
            Ok(Ok(Some(notification))) => Ok(Some(notification.data)),
            Ok(Ok(None)) => Ok(None),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::Timeout(timeout.as_millis() as u64)),
        }
    }
}

fn decode_op_result(op_result: u8) -> &'static str {
    match op_result {
        0 => "UNKNOWN_RESULT",
        2 => "ACCESS_GRANTED",
        3 => "ACCESS_REJECTED",
        6 => "DOOR_IN_OFFICE",
        7 => "PIN_REQUIRED",
        10 => "END_OFFICE",
        11 => "CANCELLED_KEY",
        14 => "OPENING_ROLLER",
        18 => "CLOSING_ROLLER",
        22 => "STOP_ROLLER",
        26 => "WAIT_SECOND_CARD",
        27 => "FINGER_REQUIRED",
        30 => "KEY_PROCESSED",
        _ => "UNKNOWN",
    }
}

fn decode_op_result_group(op_result: u8) -> &'static str {
    match op_result & 3 {
        0 => "UNKNOWN",
        1 => "FAILURE",
        2 => "ACCEPTED",
        3 => "REJECTED",
        _ => "INVALID",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Notification;
    use mkey_core::ProtocolFlags;

    /// What the fake lock does when the protocol info is read.
    enum ProtocolInfo {
        /// Answer with these bytes.
        Value(Vec<u8>),
        /// Fail the read, as a lock that dropped the link would.
        Fails,
        /// Never answer, so the read has to time out.
        Silent,
    }

    /// A lock that only knows how to be connected to and interrogated.
    ///
    /// Everything the session does before it subscribes is observable here:
    /// which bytes were written, and how many times the notify characteristic
    /// was read.
    struct FakeLock {
        advertised_version: u8,
        notify_readable: bool,
        protocol_info: ProtocolInfo,
        write_fails: bool,
        writes: Vec<Vec<u8>>,
        reads: usize,
    }

    impl FakeLock {
        fn new(advertised_version: u8, protocol_info: ProtocolInfo) -> Self {
            Self {
                advertised_version,
                notify_readable: true,
                protocol_info,
                write_fails: false,
                writes: Vec::new(),
                reads: 0,
            }
        }

        fn answering(advertised_version: u8, major: u8) -> Self {
            Self::new(
                advertised_version,
                ProtocolInfo::Value(vec![0x01, 0x00, major]),
            )
        }
    }

    impl BleTransport for FakeLock {
        async fn scan(&self, _duration: Duration) -> Result<Vec<DiscoveredLock>, Error> {
            unimplemented!("the tests connect by id")
        }

        async fn scan_and_connect(
            &mut self,
            _timeout: Duration,
            _filter: Option<LockFilter>,
        ) -> Result<ConnectedLock, Error> {
            unimplemented!("the tests connect by id")
        }

        async fn connect_by_id(
            &mut self,
            lock_id: &str,
            _timeout: Duration,
        ) -> Result<ConnectedLock, Error> {
            Ok(ConnectedLock {
                info: DiscoveredLock {
                    id: lock_id.to_string(),
                    name: None,
                    rssi: None,
                    protocol_version: self.advertised_version,
                    flags: ProtocolFlags::default(),
                },
            })
        }

        async fn disconnect(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn is_connected(&self) -> bool {
            true
        }

        async fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.writes.push(data.to_vec());
            if self.write_fails {
                return Err(Error::Disconnected);
            }
            Ok(())
        }

        async fn receive(&mut self) -> Result<Option<Notification>, Error> {
            unimplemented!("the tests stop before the exchange")
        }

        async fn subscribe(&mut self) -> Result<(), Error> {
            unimplemented!("the tests stop before the exchange")
        }

        async fn read_notify_value(&mut self) -> Result<Vec<u8>, Error> {
            self.reads += 1;
            match &self.protocol_info {
                ProtocolInfo::Value(bytes) => Ok(bytes.clone()),
                ProtocolInfo::Fails => Err(Error::Disconnected),
                ProtocolInfo::Silent => std::future::pending().await,
            }
        }

        fn notify_readable(&self) -> bool {
            self.notify_readable
        }
    }

    /// Connect with the given detection mode and report what the lock saw.
    async fn detect(lock: FakeLock, detection: Detection) -> (u8, Vec<Vec<u8>>, usize) {
        let mut session = SaltoLock::with_transport(lock).with_detection(detection);
        let version = session
            .connect_by_id("fake", None)
            .await
            .expect("connect")
            .protocol_version;

        (version, session.transport.writes, session.transport.reads)
    }

    #[tokio::test(start_paused = true)]
    async fn auto_announces_the_app_protocol_to_a_lock_that_advertises_one() {
        let (version, writes, reads) = detect(FakeLock::answering(2, 2), Detection::Auto).await;

        assert_eq!(writes, vec![APP_PROTOCOL_REQUEST.to_vec()]);
        assert_eq!(reads, 1);
        assert_eq!(version, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn auto_stays_silent_with_a_lock_found_by_service_uuid_alone() {
        // This is the lock from the field: it acknowledges `c0 01 01` and then
        // drops the link, and it advertises no SALTO manufacturer record.
        let (version, writes, reads) = detect(FakeLock::answering(0, 2), Detection::Auto).await;

        assert!(writes.is_empty(), "nothing may be written before the read");
        assert_eq!(reads, 1);
        assert_eq!(version, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn read_only_never_writes_even_for_an_advertised_lock() {
        let (version, writes, reads) = detect(FakeLock::answering(2, 1), Detection::ReadOnly).await;

        assert!(writes.is_empty());
        assert_eq!(reads, 1);
        assert_eq!(version, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn none_asks_nothing_and_keeps_the_advertised_version() {
        let (version, writes, reads) = detect(FakeLock::answering(2, 1), Detection::None).await;

        assert!(writes.is_empty());
        assert_eq!(reads, 0);
        assert_eq!(version, 2, "the advertised version is left alone");
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_app_protocol_write_is_not_fatal() {
        let mut lock = FakeLock::answering(2, 2);
        lock.write_fails = true;

        let (version, writes, reads) = detect(lock, Detection::AppProtocol).await;

        assert_eq!(writes, vec![APP_PROTOCOL_REQUEST.to_vec()]);
        assert_eq!(reads, 1, "the read still happens");
        assert_eq!(version, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unreadable_notify_characteristic_leaves_the_version_alone() {
        let mut lock = FakeLock::answering(2, 1);
        lock.notify_readable = false;

        let (version, writes, reads) = detect(lock, Detection::AppProtocol).await;

        assert!(writes.is_empty(), "no point announcing what cannot be read");
        assert_eq!(reads, 0);
        assert_eq!(version, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_read_leaves_the_version_alone() {
        let lock = FakeLock::new(2, ProtocolInfo::Fails);

        let (version, _writes, reads) = detect(lock, Detection::AppProtocol).await;

        assert_eq!(reads, 1);
        assert_eq!(version, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_lock_times_out_without_failing_the_connection() {
        let lock = FakeLock::new(0, ProtocolInfo::Silent);

        let (version, _writes, reads) = detect(lock, Detection::Auto).await;

        assert_eq!(reads, 1);
        assert_eq!(version, 0, "still unknown, which runs the v0200 flow");
    }

    #[tokio::test(start_paused = true)]
    async fn protocol_info_of_an_unexpected_shape_is_ignored() {
        for info in [vec![], vec![0x01, 0x00], vec![0x02, 0x00, 0x01]] {
            let lock = FakeLock::new(2, ProtocolInfo::Value(info.clone()));

            let (version, _writes, reads) = detect(lock, Detection::ReadOnly).await;

            assert_eq!(reads, 1);
            assert_eq!(
                version, 2,
                "unexpected shape {info:02X?} must not change the version"
            );
        }
    }
}
