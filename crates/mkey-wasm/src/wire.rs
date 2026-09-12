//! The shapes that cross into JavaScript.
//!
//! Written out by hand rather than derived on [`mkey_session`]'s own types,
//! for two reasons: the JavaScript side is a published interface that should
//! not move every time an internal enum gains a variant, and the spellings
//! here have to match the ones the TypeScript port already uses
//! (`'detecting-version'`, `'invalid-crc'`, and so on).

use mkey_session::{Action, Error, Outcome, TimerId, Trace};
use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum WireAction {
    /// Write the app protocol request. A failure is reported as a trace, not
    /// as an error, and the next action still runs.
    AnnounceAppProtocol,
    #[serde(rename_all = "camelCase")]
    ReadProtocolInfo {
        timeout_ms: u32,
    },
    Subscribe,
    Write {
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    Pause {
        ms: u32,
    },
    #[serde(rename_all = "camelCase")]
    SetTimer {
        id: &'static str,
        after_ms: u32,
    },
    Phase {
        phase: &'static str,
    },
    Trace(WireTrace),
    Done {
        result: WireResult,
    },
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum WireTrace {
    Rx {
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    Tx {
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    Read {
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    Info {
        message: String,
    },
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum WireResult {
    Ok { ok: WireOutcome },
    Err { error: WireError },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WireOutcome {
    pub protocol_version: u8,
    pub op_result: Option<u8>,
    pub op_result_name: &'static str,
    pub group: &'static str,
    pub accepted: bool,
}

#[derive(Serialize)]
pub struct WireError {
    /// One of the `SaltoErrorCode` values.
    pub code: &'static str,
    pub message: String,
}

impl From<Action> for WireAction {
    fn from(action: Action) -> Self {
        match action {
            Action::AnnounceAppProtocol => Self::AnnounceAppProtocol,
            Action::ReadProtocolInfo { timeout_ms } => Self::ReadProtocolInfo { timeout_ms },
            Action::Subscribe => Self::Subscribe,
            Action::Write(bytes) => Self::Write { bytes },
            Action::Pause { ms } => Self::Pause { ms },
            Action::SetTimer { id, after_ms } => Self::SetTimer {
                id: timer_id(id),
                after_ms,
            },
            Action::Phase(phase) => Self::Phase {
                phase: phase.as_str(),
            },
            Action::Trace(trace) => Self::Trace(match trace {
                Trace::Rx(bytes) => WireTrace::Rx { bytes },
                Trace::Tx(bytes) => WireTrace::Tx { bytes },
                Trace::Read(bytes) => WireTrace::Read { bytes },
                Trace::Info(message) => WireTrace::Info { message },
            }),
            Action::Done(result) => Self::Done {
                result: match result {
                    Ok(outcome) => WireResult::Ok {
                        ok: outcome_of(&outcome),
                    },
                    Err(e) => WireResult::Err {
                        error: WireError {
                            code: e.code().as_str(),
                            message: e.to_string(),
                        },
                    },
                },
            },
        }
    }
}

fn outcome_of(outcome: &Outcome) -> WireOutcome {
    WireOutcome {
        protocol_version: outcome.protocol_version,
        op_result: outcome.op_result,
        op_result_name: outcome.op_result_name(),
        group: outcome.group.as_str(),
        accepted: outcome.accepted,
    }
}

pub const fn timer_id(id: TimerId) -> &'static str {
    match id {
        TimerId::FirstPacket => "first-packet",
        TimerId::Packet => "packet",
        TimerId::AfterFinalResult => "after-final-result",
    }
}

/// Parse a timer id coming back from JavaScript.
pub fn parse_timer_id(id: &str) -> Result<TimerId, Error> {
    match id {
        "first-packet" => Ok(TimerId::FirstPacket),
        "packet" => Ok(TimerId::Packet),
        "after-final-result" => Ok(TimerId::AfterFinalResult),
        other => Err(Error::InvalidData(format!("unknown timer id {other}"))),
    }
}
