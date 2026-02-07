use crate::command::justin::{JustinProtocolManager, JustinState, NoopKeyStore};
use crate::crypto::encrypt_aes_cbc;
use crate::data::mobile_key::{GeneralPurposeTag, MobileKey, Permissions};
use crate::stack::JustinStack0100;
use crate::transport::{
    BleTransport, BtleplugTransport, ConnectedLock, DiscoveredLock, LockFilter,
};
use crate::Error;
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

pub struct SaltoLock {
    transport: BtleplugTransport,
    connected_lock: Option<ConnectedLock>,
    stack: Option<JustinStack0100<NoopKeyStore>>,
    mobile_key_v0100: Option<MobileKey>,
    state: LockState,
}

impl SaltoLock {
    pub async fn new() -> Result<Self, Error> {
        let transport = BtleplugTransport::new().await?;
        Ok(Self {
            transport,
            connected_lock: None,
            stack: None,
            mobile_key_v0100: None,
            state: LockState::Disconnected,
        })
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
    ///              the filter returns `true` will be connected to.
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

        self.connected_lock = Some(connected);
        self.stack = None;
        self.mobile_key_v0100 = None;
        self.state = LockState::Connected;

        Ok(&self.connected_lock.as_ref().unwrap().info)
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

        self.connected_lock = Some(connected);
        self.stack = None;
        self.mobile_key_v0100 = None;
        self.state = LockState::Connected;

        Ok(&self.connected_lock.as_ref().unwrap().info)
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
                let ssp = crate::security::ssp::SecureProtocolManager::new(mobile_key.kn_key);
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
        self.transport.ensure_subscribed().await?;

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

        self.transport.ensure_subscribed().await?;

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
