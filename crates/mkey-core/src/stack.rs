//! v0200 protocol stack glue (SSP + Justin command layer).
//!
//! In the Java SDK this corresponds to `JustinStack0100`, which takes the raw
//! BLE notifications from the lock and returns the next bytes to write back.

use crate::command::justin::{JustinProtocolManager, JustinState, MobileKeyStore};
use crate::security::ssp::{control, SecureProtocolManager, SspState};
use crate::Error;

/// Combined protocol stack used by BLE v0200 locks.
///
/// Input: raw bytes received from the lock (BLE notification payload).
/// Output: raw bytes to write back to the lock.
pub struct JustinStack0100<S: MobileKeyStore> {
    ssp: SecureProtocolManager,
    justin: JustinProtocolManager<S>,
}

impl<S: MobileKeyStore> JustinStack0100<S> {
    pub fn new(ssp: SecureProtocolManager, justin: JustinProtocolManager<S>) -> Self {
        Self { ssp, justin }
    }

    pub fn ssp_state(&self) -> SspState {
        self.ssp.state()
    }

    pub fn justin_state(&self) -> JustinState {
        self.justin.state()
    }

    /// The SSP layer (state, session key, IV chain).
    pub fn ssp(&self) -> &SecureProtocolManager {
        &self.ssp
    }

    pub fn justin(&self) -> &JustinProtocolManager<S> {
        &self.justin
    }

    pub fn justin_mut(&mut self) -> &mut JustinProtocolManager<S> {
        &mut self.justin
    }

    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        if packet.len() < 2 {
            return Err(Error::InvalidData("SSP packet too short".to_string()));
        }

        let control_byte = packet[0];
        let is_control = (control_byte & control::REQUEST_FLAG) != 0;
        let is_encrypted = (control_byte & control::ENCRYPTED_FLAG) != 0;

        if is_control {
            // Control packets are owned by SSP (OpenSessionStep1/2, GetVersion, ...).
            return self.ssp.process_packet(packet);
        }

        if is_encrypted {
            // Encrypted data packets must be inside a secure session.
            let plaintext = self.ssp.process_packet(packet)?;
            let response_payload = self.process_justin(&plaintext, true)?;
            return self.ssp.wrap_data(&response_payload);
        }

        // Unencrypted data packet: forward to Justin without SSP session requirement.
        let response_payload = self.process_justin(&packet[1..], false)?;
        let mut out = Vec::with_capacity(1 + response_payload.len());
        out.push(control_byte);
        out.extend_from_slice(&response_payload);
        Ok(out)
    }

    fn process_justin(&mut self, payload: &[u8], secure_session: bool) -> Result<Vec<u8>, Error> {
        eprintln!(
            "[JUSTIN] Processing command: {:02X?} (secure={})",
            payload, secure_session
        );
        // The Java SDK passes the "secure session" context per-packet, based on
        // the encrypted flag, not on SSP state.
        let prev = self.justin.is_secure_session();
        self.justin.set_secure_session(secure_session);
        let res = self.justin.process_command(payload);
        if let Ok(ref response) = res {
            eprintln!("[JUSTIN] Response: {:02X?}", response);
        }
        self.justin.set_secure_session(prev);
        res
    }
}
