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
}

impl<S: MobileKeyStore> JustinProtocolManager<S> {
    pub fn new(key_store: S) -> Self {
        Self {
            state: JustinState::Ready,
            key_store,
            current_key: None,
            secure_session: false,
            last_audit_op_result: None,
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

    pub fn reset(&mut self) {
        self.state = JustinState::Ready;
        self.current_key = None;
        self.secure_session = false;
        self.last_audit_op_result = None;
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
        let identifier = self.compute_key_identifier(key_id);

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
                decode_op_result_group(op_result)
            );
            if data.len() > 1 {
                eprintln!("[LOCK RESULT] Additional data: {:02X?}", &data[1..]);
            }
        }

        Ok(vec![CommandStatus::Success.into()])
    }

    fn compute_key_identifier(&self, key_id: &[u8]) -> String {
        let hash = crc16_hasher(key_id);

        let mut base62_input = [0u8; 10];
        base62_input[0..8].copy_from_slice(&key_id[0..8]);
        base62_input[8] = hash[0];
        base62_input[9] = hash[hash.len() - 1];

        encode_base62(&base62_input)
    }

    fn can_read_tag(&self, tag_id: u8, permissions: Permissions) -> bool {
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

const TAG_AUDIT: u8 = 0x0B;

/// Decode OpResult from the lock
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

fn is_legacy_tag(tag_id: u8) -> bool {
    // Matches Java SDK's `MobileKeyTransformer`: only tags 0x00..0x02 are treated as legacy.
    // These are returned without permission checks and are never writable.
    matches!(tag_id, 0x00 | 0x01 | 0x02)
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
        }
    }
}
