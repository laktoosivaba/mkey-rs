//! What crosses the line between the session and its shell.

use mkey_core::{decode_op_result, Error, OpResultGroup};

/// How the session works out which stack the lock speaks, before it subscribes.
///
/// [`Detection::AppProtocol`] is the reference sequence: announce the app
/// protocol, then read the protocol info back. The other two exist because a
/// lock can drop the link during that handshake, and the only way to tell
/// which half it objected to is to leave one out. A failed detection is never
/// fatal in any of the three — the version simply stays unknown, which runs
/// the v0200 flow.
///
/// Picking a mode from the advertisement is the shell's job: only the shell
/// has seen an advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Detection {
    #[default]
    AppProtocol,
    ReadOnly,
    None,
}

/// What the holder is asking the lock to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Normal open.
    #[default]
    Standard,
    /// Toggle office mode: the door stays unlocked until toggled again.
    Office,
}

/// How far along one opening attempt is.
///
/// [`Phase::Finished`] is reported on every exit path, successful or not: it
/// means "the session is over and the link is being torn down", not "the door
/// opened".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    DetectingVersion,
    Authenticating,
    Exchanging,
    Finished,
}

impl Phase {
    /// The spelling the TypeScript port uses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DetectingVersion => "detecting-version",
            Self::Authenticating => "authenticating",
            Self::Exchanging => "exchanging",
            Self::Finished => "finished",
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which wait a timer belongs to. At most one is ever pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerId {
    /// The very first packet after notifications were enabled.
    FirstPacket,
    /// Every packet after the first.
    Packet,
    /// The grace period for an optional `CLOSE` after the lock reported its result.
    AfterFinalResult,
}

/// One observation from a running session.
///
/// `Rx`/`Tx` carry the packets exchanged once notifications are enabled — the
/// exact span a fixture records. `Read` carries the protocol info, `Info`
/// everything that has no bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trace {
    Rx(Vec<u8>),
    Tx(Vec<u8>),
    Read(Vec<u8>),
    Info(String),
}

/// How long the lock is given at each step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Reading the protocol info from the notify characteristic.
    pub protocol_info_read_ms: u32,
    /// Waiting for the very first packet after notifications are enabled.
    pub first_packet_ms: u32,
    /// Waiting for every following packet.
    pub packet_ms: u32,
    /// Grace period for an optional `CLOSE` after the lock reported its result.
    pub after_final_result_ms: u32,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            protocol_info_read_ms: 1_000,
            first_packet_ms: 30_000,
            packet_ms: 10_000,
            after_final_result_ms: 3_000,
        }
    }
}

/// Everything the shell knows that the session needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub mode: Mode,
    pub detection: Detection,
    pub timeouts: Timeouts,
    /// Whether the notify characteristic advertises the READ property. When it
    /// does not, the protocol info cannot be read and the version stays unknown.
    pub notify_readable: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            detection: Detection::default(),
            timeouts: Timeouts::default(),
            notify_readable: true,
        }
    }
}

/// How the lock answered.
///
/// A rejection is not an error: the lock was asked and said no, which is
/// [`OpResultGroup::Rejected`] rather than a failure to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// Major protocol version the session ran: 1 or 2.
    pub protocol_version: u8,
    /// `None` when the lock ended the session without reporting a result.
    pub op_result: Option<u8>,
    pub group: OpResultGroup,
    pub accepted: bool,
}

impl Outcome {
    pub(crate) fn new(protocol_version: u8, op_result: Option<u8>) -> Self {
        let group = op_result.map(OpResultGroup::of).unwrap_or_default();

        Self {
            protocol_version,
            op_result,
            group,
            accepted: group.is_accepted(),
        }
    }

    /// Human readable name of the result, or `UNKNOWN` when there is none.
    pub fn op_result_name(&self) -> &'static str {
        self.op_result.map(decode_op_result).unwrap_or("UNKNOWN")
    }
}

/// Something that happened to the link, or to the clock.
#[derive(Debug)]
pub enum Event<'a> {
    /// The link is up and the session may begin.
    Started,
    /// The protocol info read finished. `None` means it did not produce bytes,
    /// for any reason — the session treats that as "version unknown", never as
    /// a failure.
    ProtocolInfo(Option<&'a [u8]>),
    /// A notification arrived from the lock.
    Notification(&'a [u8]),
    /// The pending timer expired.
    Timer(TimerId),
    /// The lock dropped the link.
    LinkClosed,
    /// The caller asked to stop.
    Aborted,
}

/// Something the shell must do, in the order given.
#[derive(Debug)]
pub enum Action {
    /// Write the BER-TLV app protocol request.
    ///
    /// **A failure here is not fatal.** At least one lock in the field
    /// acknowledges this write and then drops the link on the read that
    /// follows. Report the failure as a trace and carry on to the next action;
    /// the read will produce [`Event::ProtocolInfo`] with `None` and the
    /// version will stay unknown.
    AnnounceAppProtocol,
    /// Read the notify characteristic, bounded by `timeout_ms`, and deliver the
    /// result as [`Event::ProtocolInfo`]. Any failure is `None`, not an error.
    ReadProtocolInfo { timeout_ms: u32 },
    /// Enable notifications. From here on the lock may speak at any time.
    Subscribe,
    /// Write these bytes to the lock. A failure ends the session.
    Write(Vec<u8>),
    /// Do nothing for this long before the next action. Notifications that
    /// arrive meanwhile are queued, not dropped.
    Pause { ms: u32 },
    /// Arm a timer, replacing whichever one was pending.
    SetTimer { id: TimerId, after_ms: u32 },
    /// Report progress to the caller.
    Phase(Phase),
    /// Report one observation to the caller.
    Trace(Trace),
    /// The session is over. No further events will be accepted; the shell
    /// disconnects and hands this to its caller.
    Done(Result<Outcome, Error>),
}
