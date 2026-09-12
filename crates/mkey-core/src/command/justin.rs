//! Justin Protocol Command Layer
//!
//! Implements the command layer that sits above SSP, handling:
//! - OPEN: Establish session with mobile key
//! - CLOSE: Close active session
//! - READ_TAG: Read data from a key tag
//! - WRITE_TAG: Write data to a key tag

use crate::crypto::crc16_hasher;
use crate::data::base62::encode_base62;
use crate::data::mobile_key::{MobileKey, Permissions};
use crate::error::Error;
use crate::op_result::{decode_op_result, OpResultGroup};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandOpCode {
    Open = 0x00,
    Close = 0x01,
    ReadTag = 0x02,
    WriteTag = 0x03,
}

impl TryFrom<u8> for CommandOpCode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            0x00 => Ok(CommandOpCode::Open),
            0x01 => Ok(CommandOpCode::Close),
            0x02 => Ok(CommandOpCode::ReadTag),
            0x03 => Ok(CommandOpCode::WriteTag),
            _ => Err(Error::InvalidData(format!(
                "Unknown command OpCode: 0x{:02X}",
                value
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandStatus {
    Success = 0x00,
    GenericError = 0x01,
    NotFound = 0x02,
}

impl From<CommandStatus> for u8 {
    fn from(status: CommandStatus) -> u8 {
        status as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JustinState {
    Ready,
    Connected,
}

impl std::fmt::Display for JustinState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JustinState::Ready => write!(f, "READY"),
            JustinState::Connected => write!(f, "CONNECTED"),
        }
    }
}

pub trait MobileKeyStore {
    fn get_key(&self, identifier: &str) -> Option<MobileKey>;
}

/// A `MobileKeyStore` implementation that never resolves keys.
///
/// Useful when the mobile key is preselected (BLE v0200 flow), so the stack
/// never needs to resolve a key via the OPEN command.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopKeyStore;

impl MobileKeyStore for NoopKeyStore {
    fn get_key(&self, _identifier: &str) -> Option<MobileKey> {
        None
    }
}

pub struct JustinProtocolManager<S: MobileKeyStore> {
    state: JustinState,
    key_store: S,
    current_key: Option<MobileKey>,
    secure_session: bool,
    last_audit_op_result: Option<u8>,
    kn_read_refusals: u32,
}

impl<S: MobileKeyStore> JustinProtocolManager<S> {
    pub fn new(key_store: S) -> Self {
        Self {
            state: JustinState::Ready,
            key_store,
            current_key: None,
            secure_session: false,
            last_audit_op_result: None,
            kn_read_refusals: 0,
        }
    }

    pub fn state(&self) -> JustinState {
        self.state
    }

    pub fn set_secure_session(&mut self, secure: bool) {
        self.secure_session = secure;
    }

    pub fn is_secure_session(&self) -> bool {
        self.secure_session
    }

    pub fn current_key(&self) -> Option<&MobileKey> {
        self.current_key.as_ref()
    }

    pub fn current_key_mut(&mut self) -> Option<&mut MobileKey> {
        self.current_key.as_mut()
    }

    pub fn last_audit_op_result(&self) -> Option<u8> {
        self.last_audit_op_result
    }

    /// How many times the lock has been refused the kN key so far.
    ///
    /// A lock asking for tag `0x02` outside a secure session is either running
    /// an old firmware or is not the lock it claims to be; either way the
    /// session carries on, and the count is what lets a caller notice.
    pub fn refused_kn_reads(&self) -> u32 {
        self.kn_read_refusals
    }

    pub fn reset(&mut self) {
        self.state = JustinState::Ready;
        self.current_key = None;
        self.secure_session = false;
        self.last_audit_op_result = None;
        self.kn_read_refusals = 0;
    }

    pub fn process_command(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.is_empty() {
            return Err(Error::InvalidData("Empty command".to_string()));
        }

        let opcode = CommandOpCode::try_from(data[0])?;
        let payload = &data[1..];

        match opcode {
            CommandOpCode::Open => self.handle_open(payload),
            CommandOpCode::Close => self.handle_close(payload),
            CommandOpCode::ReadTag => self.handle_read_tag(payload),
            CommandOpCode::WriteTag => self.handle_write_tag(payload),
        }
    }

    fn handle_open(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if self.state == JustinState::Connected {
            return Ok(vec![CommandStatus::GenericError.into()]);
        }

        if payload.len() < 8 {
            return Ok(vec![CommandStatus::GenericError.into()]);
        }

        let key_id = &payload[0..8];
        let identifier = compute_key_identifier(key_id);

        match self.key_store.get_key(&identifier) {
            Some(key) => {
                self.current_key = Some(key);
                self.state = JustinState::Connected;
                Ok(vec![CommandStatus::Success.into()])
            }
            None => Ok(vec![CommandStatus::NotFound.into()]),
        }
    }

    fn handle_close(&mut self, _payload: &[u8]) -> Result<Vec<u8>, Error> {
        if self.state != JustinState::Connected {
            return Ok(vec![CommandStatus::GenericError.into()]);
        }

        self.state = JustinState::Ready;

        Ok(vec![CommandStatus::Success.into()])
    }

    fn handle_read_tag(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if self.state != JustinState::Connected {
            return Ok(vec![CommandStatus::GenericError.into()]);
        }

        if payload.is_empty() {
            return Ok(vec![CommandStatus::GenericError.into()]);
        }

        let tag_id = payload[0];
        eprintln!("[JUSTIN] Lock READ_TAG 0x{:02X}", tag_id);

        let key = match &self.current_key {
            Some(k) => k,
            None => return Ok(vec![CommandStatus::GenericError.into()]),
        };

        let tag = match key.get_tag(tag_id) {
            Some(t) => t,
            None => {
                eprintln!("[JUSTIN] Tag 0x{:02X} NOT_FOUND", tag_id);
                return Ok(vec![CommandStatus::NotFound.into()]);
            }
        };

        if self.refuses_kn_key(tag_id) {
            self.kn_read_refusals += 1;
            eprintln!("[JUSTIN] Refused to hand out the kN key outside a secure session");
            return Ok(vec![CommandStatus::GenericError.into()]);
        }

        if !self.can_read_tag(tag_id, tag.permissions) {
            if !tag.permissions.contains(Permissions::READABLE) {
                return Ok(vec![CommandStatus::NotFound.into()]);
            }
            return Ok(vec![CommandStatus::GenericError.into()]);
        }

        let mut response = Vec::with_capacity(1 + tag.data.len());
        response.push(CommandStatus::Success.into());
        response.extend_from_slice(&tag.data);

        Ok(response)
    }

    fn handle_write_tag(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if self.state != JustinState::Connected {
            return Ok(vec![CommandStatus::GenericError.into()]);
        }

        if payload.len() < 2 {
            return Ok(vec![CommandStatus::GenericError.into()]);
        }

        let tag_id = payload[0];
        let data = &payload[1..];
        eprintln!(
            "[JUSTIN] Lock WRITE_TAG 0x{:02X} data={:02X?}",
            tag_id, data
        );

        if is_legacy_tag(tag_id) {
            return Ok(vec![CommandStatus::GenericError.into()]);
        }

        let permissions = {
            let key = match &self.current_key {
                Some(k) => k,
                None => return Ok(vec![CommandStatus::GenericError.into()]),
            };

            match key.get_tag(tag_id) {
                Some(t) => t.permissions,
                None => return Ok(vec![CommandStatus::NotFound.into()]),
            }
        };

        if !self.can_write_tag(tag_id, permissions) {
            if !permissions.contains(Permissions::WRITABLE) {
                return Ok(vec![CommandStatus::NotFound.into()]);
            }
            return Ok(vec![CommandStatus::GenericError.into()]);
        }

        if let Some(key) = &mut self.current_key {
            key.set_tag_data(tag_id, data.to_vec());
        }

        // Log operation result when lock writes to audit tag
        if tag_id == TAG_AUDIT && !data.is_empty() {
            let op_result = data[0];
            self.last_audit_op_result = Some(op_result);
            eprintln!(
                "[LOCK RESULT] OpResult={} ({}) Group={}",
                op_result,
                decode_op_result(op_result),
                OpResultGroup::of(op_result)
            );
            if data.len() > 1 {
                eprintln!("[LOCK RESULT] Additional data: {:02X?}", &data[1..]);
            }
        }

        Ok(vec![CommandStatus::Success.into()])
    }

    /// The pre-shared kN key is served inside a secure session only, where the
    /// peer has already proven it knows that key.
    ///
    /// This deviates from the vendor SDK, which treats `0x02` as a legacy tag
    /// readable by anyone that has managed to connect. Handing the key that
    /// authenticates the session to an unauthenticated peer defeats the point
    /// of having one. The browser port has always behaved this way; the
    /// deviation is now shared rather than divergent.
    fn refuses_kn_key(&self, tag_id: u8) -> bool {
        tag_id == TAG_KN_KEY && !self.secure_session
    }

    fn can_read_tag(&self, tag_id: u8, permissions: Permissions) -> bool {
        if self.refuses_kn_key(tag_id) {
            return false;
        }

        if is_legacy_tag(tag_id) {
            return true;
        }

        if !permissions.contains(Permissions::READABLE) {
            return false;
        }

        if self.secure_session {
            return true;
        }

        permissions.contains(Permissions::READ_WITHOUT_SECURITY)
    }

    fn can_write_tag(&self, tag_id: u8, permissions: Permissions) -> bool {
        if is_legacy_tag(tag_id) {
            return false;
        }

        // Audit tag (0x0B) is always writable - the lock writes operation results here
        if tag_id == TAG_AUDIT {
            return true;
        }

        if !permissions.contains(Permissions::WRITABLE) {
            return false;
        }

        if self.secure_session {
            return true;
        }

        permissions.contains(Permissions::WRITE_WITHOUT_SECURITY)
    }
}

/// Audit tag id. The lock writes the operation result here.
pub const TAG_AUDIT: u8 = 0x0B;

/// Tag id of the pre-shared kN key.
pub const TAG_KN_KEY: u8 = 0x02;

/// Derive the key-store lookup identifier for an 8-byte key id.
///
/// `base62(keyId ‖ crc16Hasher(keyId))`, matching the OPEN command in the
/// Java SDK.
///
/// # Panics
/// Panics if `key_id` is shorter than 8 bytes.
pub fn compute_key_identifier(key_id: &[u8]) -> String {
    let hash = crc16_hasher(key_id);

    let mut base62_input = [0u8; 10];
    base62_input[0..8].copy_from_slice(&key_id[0..8]);
    base62_input[8] = hash[0];
    base62_input[9] = hash[hash.len() - 1];

    encode_base62(&base62_input)
}

/// Decode OpResult from the lock
fn is_legacy_tag(tag_id: u8) -> bool {
    // Matches Java SDK's `MobileKeyTransformer`: only tags 0x00..0x02 are treated as legacy.
    // These are returned without permission checks and are never writable.
    matches!(tag_id, 0x00..=0x02)
}

impl JustinProtocolManager<NoopKeyStore> {
    /// BLE v0200 flow: the mobile key is already selected by the application.
    ///
    /// The lock starts sending READ_TAG/WRITE_TAG immediately (often before SSP),
    /// so we start in CONNECTED with the key loaded.
    pub fn new_with_key(key: MobileKey) -> Self {
        Self {
            state: JustinState::Connected,
            key_store: NoopKeyStore,
            current_key: Some(key),
            secure_session: false,
            last_audit_op_result: None,
            kn_read_refusals: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `base62(keyId ‖ crc16Hasher(keyId))`, cross-checked against an
    /// independent implementation.
    #[test]
    fn key_identifiers_match_reference_values() {
        for (key_id, expected) in [
            ("0011223344556677", "64zDKgN3bBMp"),
            ("0000000000000000", "7GX"),
            ("ffffffffffffffff", "62IeP5BU9vzmio"),
            ("3132333435363738", "1a0AFzKIBiaui4"),
        ] {
            let bytes = hex::decode(key_id).unwrap();
            assert_eq!(compute_key_identifier(&bytes), expected, "key id {key_id}");
        }
    }

    #[test]
    fn command_opcodes_reject_unknown_values() {
        assert_eq!(CommandOpCode::try_from(0x00).unwrap(), CommandOpCode::Open);
        assert_eq!(
            CommandOpCode::try_from(0x03).unwrap(),
            CommandOpCode::WriteTag
        );
        assert!(matches!(
            CommandOpCode::try_from(0x04),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn the_kn_key_is_refused_outside_a_secure_session() {
        let mut justin = JustinProtocolManager::new_with_key(MobileKey::new([0x42u8; 16]));
        justin.set_secure_session(false);

        // READ_TAG 0x02 — the pre-shared kN key.
        assert_eq!(
            justin.process_command(&[0x02, TAG_KN_KEY]).unwrap(),
            vec![CommandStatus::GenericError as u8]
        );
        assert_eq!(justin.refused_kn_reads(), 1);

        justin.process_command(&[0x02, TAG_KN_KEY]).unwrap();
        assert_eq!(justin.refused_kn_reads(), 2);
    }

    #[test]
    fn the_kn_key_is_served_inside_a_secure_session() {
        let key = MobileKey::new([0x42u8; 16]);
        let expected = key.kn_key.to_vec();
        let mut justin = JustinProtocolManager::new_with_key(key);
        justin.set_secure_session(true);

        let response = justin.process_command(&[0x02, TAG_KN_KEY]).unwrap();

        assert_eq!(response[0], CommandStatus::Success as u8);
        assert_eq!(&response[1..], &expected[..]);
        assert_eq!(justin.refused_kn_reads(), 0);
    }

    #[test]
    fn only_tags_0x00_to_0x02_are_legacy() {
        for id in 0x00u8..=0x02 {
            assert!(is_legacy_tag(id));
        }
        for id in [0x03u8, 0x05, 0x0A, 0x0B, 0x10, 0xFF] {
            assert!(!is_legacy_tag(id));
        }
    }

    #[test]
    fn op_result_names_and_groups() {
        assert_eq!(decode_op_result(2), "ACCESS_GRANTED");
        assert_eq!(decode_op_result(3), "ACCESS_REJECTED");
        assert_eq!(decode_op_result(6), "DOOR_IN_OFFICE");
        assert_eq!(decode_op_result(99), "UNKNOWN");
        assert_eq!(OpResultGroup::of(2), OpResultGroup::Accepted);
        assert_eq!(OpResultGroup::of(6), OpResultGroup::Accepted);
        assert_eq!(OpResultGroup::of(3), OpResultGroup::Rejected);
        assert_eq!(OpResultGroup::of(1), OpResultGroup::Failure);
        assert_eq!(OpResultGroup::of(0), OpResultGroup::Unknown);
    }

    #[test]
    fn an_empty_command_is_an_error_but_a_bad_state_is_only_a_status_byte() {
        let mut justin = JustinProtocolManager::new(NoopKeyStore);
        assert!(matches!(
            justin.process_command(&[]),
            Err(Error::InvalidData(_))
        ));
        // Not connected: CLOSE / READ_TAG / WRITE_TAG answer GenericError
        // instead of failing the packet.
        assert_eq!(justin.process_command(&[0x01]).unwrap(), vec![0x01]);
        assert_eq!(justin.process_command(&[0x02, 0x00]).unwrap(), vec![0x01]);
        assert_eq!(
            justin.process_command(&[0x03, 0x05, 0x01]).unwrap(),
            vec![0x01]
        );
    }

    #[test]
    fn open_reports_not_found_when_the_store_has_no_key() {
        let mut justin = JustinProtocolManager::new(NoopKeyStore);
        assert_eq!(
            justin
                .process_command(&[0x00, 1, 2, 3, 4, 5, 6, 7, 8])
                .unwrap(),
            vec![0x02]
        );
        assert_eq!(justin.state(), JustinState::Ready);
        // Too short for a key id.
        assert_eq!(justin.process_command(&[0x00, 1, 2]).unwrap(), vec![0x01]);
    }

    #[test]
    fn close_moves_back_to_ready_exactly_once() {
        let key = MobileKey::new([0u8; 16]);
        let mut justin = JustinProtocolManager::new_with_key(key);
        assert_eq!(justin.state(), JustinState::Connected);
        assert_eq!(justin.process_command(&[0x01]).unwrap(), vec![0x00]);
        assert_eq!(justin.state(), JustinState::Ready);
        assert_eq!(justin.process_command(&[0x01]).unwrap(), vec![0x01]);
    }

    #[test]
    fn writing_the_audit_tag_latches_the_op_result() {
        let key = MobileKey::new([0u8; 16]);
        let mut justin = JustinProtocolManager::new_with_key(key);
        justin
            .current_key_mut()
            .unwrap()
            .set_tag_data(TAG_AUDIT, vec![]);
        assert!(justin.last_audit_op_result().is_none());
        assert_eq!(
            justin.process_command(&[0x03, TAG_AUDIT, 2, 0xAA]).unwrap(),
            vec![0x00]
        );
        assert_eq!(justin.last_audit_op_result(), Some(2));
    }

    #[test]
    fn legacy_tags_are_never_writable() {
        let key = MobileKey::new([0u8; 16]);
        let mut justin = JustinProtocolManager::new_with_key(key);
        justin.set_secure_session(true);
        for id in 0x00u8..=0x02 {
            assert_eq!(
                justin.process_command(&[0x03, id, 0x01]).unwrap(),
                vec![0x01],
                "tag 0x{id:02X}"
            );
        }
    }
}
