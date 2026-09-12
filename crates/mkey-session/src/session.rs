//! The state machine itself.

use mkey_core::command::justin::{JustinProtocolManager, JustinState, NoopKeyStore};
use mkey_core::crypto::encrypt_aes_cbc;
use mkey_core::data::mobile_key::{GeneralPurposeTag, MobileKey, Permissions};
use mkey_core::security::random::RandomSource;
use mkey_core::security::ssp::{SecureProtocolManager, SspState};
use mkey_core::stack::JustinStack0100;
use mkey_core::{Error, OpResultGroup};

use crate::types::{
    Action, Detection, Event, Mode, Options, Outcome, Phase, Timeouts, TimerId, Trace,
};

/// BER-TLV app protocol request: private tag 0, one byte of value `0x01`.
pub const APP_PROTOCOL_REQUEST: [u8; 3] = [0xC0, 0x01, 0x01];

const PROTOCOL_INFO_PREFIX: u8 = 0x01;
const PROTOCOL_INFO_LENGTH: usize = 3;
const PROTOCOL_INFO_MAJOR_INDEX: usize = 2;

/// Tag carrying the opening mode.
const TAG_OPENING_MODE: u8 = 0x10;

/// First byte of every v0100 packet.
mod v0100_prefix {
    pub const IDENTIFY: u8 = 0x02;
    pub const NONCE: u8 = 0x03;
    pub const SIGNED_NONCE: u8 = 0x04;
    pub const RESULT: u8 = 0x05;
}

/// How long the lock is given to breathe after the long IDD+AT write.
const V0100_SETTLE_MS: u32 = 50;
const V0100_NONCE_LENGTH: usize = 16;
/// v0100 signing IV: sixteen `0xFF` bytes.
const V0100_SIGN_IV: [u8; 16] = [0xFFu8; 16];

/// Traced when the lock ends the session by dropping the link.
///
/// The fixture recorder turns it into the trailing `disconnect` step, so the
/// wording is part of the contract rather than a message to reword freely.
pub const LOCK_DISCONNECTED_MESSAGE: &str = "The lock closed the connection";

enum State {
    /// Nothing has happened yet.
    Idle,
    /// Waiting for the protocol info.
    Detecting,
    V0200(Box<V0200>),
    V0100(V0100),
}

struct V0200 {
    stack: JustinStack0100<NoopKeyStore>,
    first_packet: bool,
    final_op_result: Option<u8>,
    exchanging: bool,
    traced_kn_refusals: u32,
}

struct V0100 {
    kn_key: [u8; 16],
    step: V0100Step,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum V0100Step {
    AwaitingNonce,
    AwaitingResult,
}

impl V0100Step {
    const fn expected_prefix(self) -> u8 {
        match self {
            Self::AwaitingNonce => v0100_prefix::NONCE,
            Self::AwaitingResult => v0100_prefix::RESULT,
        }
    }
}

/// One opening attempt, as a pure state machine.
///
/// Feed it [`Event`]s, apply the [`Action`]s it returns in order, and stop when
/// it returns [`Action::Done`]. It never blocks, never reads a clock and never
/// touches a radio, which is the whole point: the same instance runs behind
/// btleplug on a desktop, behind Web Bluetooth in a browser, and against a
/// simulator in a test.
///
/// **The shell's side of the contract:**
///
/// 1. Apply actions strictly in order, each one finished before the next.
/// 2. [`Action::SetTimer`] replaces whichever timer was pending; only one is
///    ever armed.
/// 3. Notifications that arrive while actions are being applied are queued,
///    never dropped.
/// 4. After [`Action::Done`], feed no more events.
/// 5. Disconnecting is the shell's job, on every exit path — the session does
///    not know the link exists.
/// 6. Transport failures never reach the session: either feed
///    [`Event::LinkClosed`] or finish on your own. The one exception is
///    [`Event::ProtocolInfo`], which carries `None` for "could not read".
pub struct Session {
    key: MobileKey,
    options: Options,
    random: Option<Box<dyn RandomSource + Send>>,
    state: State,
    /// Whether [`Action::Done`] has been emitted. Kept beside the state rather
    /// than replacing it, so a finished session can still be inspected.
    finished: bool,
}

impl Session {
    /// A session that will draw `RandomB` from the OS CSPRNG.
    pub fn new(key: MobileKey, options: Options) -> Self {
        Self {
            key,
            options,
            random: None,
            state: State::Idle,
            finished: false,
        }
    }

    /// A session with an injected source of `RandomB`.
    ///
    /// Test tooling: it makes a whole exchange reproducible byte for byte.
    pub fn with_random(
        key: MobileKey,
        options: Options,
        random: Box<dyn RandomSource + Send>,
    ) -> Self {
        Self {
            random: Some(random),
            ..Self::new(key, options)
        }
    }

    /// Whether [`Action::Done`] has already been emitted.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// The v0200 protocol stack, once the session has started one.
    ///
    /// Test tooling. The fixture generator records the SSP session keys and
    /// the conformance suite asserts on Justin's state; an application has no
    /// use for this and should read [`Outcome`] instead.
    pub fn stack(&self) -> Option<&JustinStack0100<NoopKeyStore>> {
        match &self.state {
            State::V0200(session) => Some(&session.stack),
            _ => None,
        }
    }

    /// Hand the session one event and collect what it wants done.
    pub fn poll(&mut self, event: Event<'_>) -> Vec<Action> {
        let mut out = Vec::new();

        if self.is_finished() {
            return out;
        }

        if matches!(event, Event::Aborted) {
            self.finish(&mut out, Err(Error::Cancelled));
            return out;
        }

        match &mut self.state {
            State::Idle => self.poll_idle(event, &mut out),
            State::Detecting => self.poll_detecting(event, &mut out),
            State::V0200(_) => self.poll_v0200(event, &mut out),
            State::V0100(_) => self.poll_v0100(event, &mut out),
        }

        out
    }

    // -- detection ---------------------------------------------------------

    fn poll_idle(&mut self, event: Event<'_>, out: &mut Vec<Action>) {
        match event {
            Event::Started => {
                out.push(Action::Phase(Phase::DetectingVersion));

                if self.options.detection == Detection::None {
                    out.push(info("Version detection skipped, subscribing straight away"));
                    self.begin(None, out);
                    return;
                }

                if !self.options.notify_readable {
                    out.push(info(
                        "Notify characteristic is not readable, protocol version unknown",
                    ));
                    self.begin(None, out);
                    return;
                }

                if self.options.detection == Detection::AppProtocol {
                    out.push(Action::AnnounceAppProtocol);
                }

                out.push(Action::ReadProtocolInfo {
                    timeout_ms: self.options.timeouts.protocol_info_read_ms,
                });
                self.state = State::Detecting;
            }
            Event::LinkClosed => self.finish(out, Err(Error::Disconnected)),
            other => self.unexpected(other, "before the session started", out),
        }
    }

    fn poll_detecting(&mut self, event: Event<'_>, out: &mut Vec<Action>) {
        match event {
            Event::ProtocolInfo(Some(info_bytes)) => {
                out.push(Action::Trace(Trace::Read(info_bytes.to_vec())));

                let major = if info_bytes.len() >= PROTOCOL_INFO_LENGTH
                    && info_bytes[0] == PROTOCOL_INFO_PREFIX
                {
                    Some(info_bytes[PROTOCOL_INFO_MAJOR_INDEX])
                } else {
                    out.push(info(
                        "Protocol info has an unexpected shape, protocol version unknown",
                    ));
                    None
                };

                self.begin(major, out);
            }
            Event::ProtocolInfo(None) => {
                out.push(info("Protocol info read failed, protocol version unknown"));
                self.begin(None, out);
            }
            Event::LinkClosed => self.finish(out, Err(Error::Disconnected)),
            other => self.unexpected(other, "while detecting the protocol version", out),
        }
    }

    /// Enable notifications and start the flow the detected version calls for.
    fn begin(&mut self, major: Option<u8>, out: &mut Vec<Action>) {
        if let Some(version) = major {
            if version != 1 && version != 2 {
                self.finish(
                    out,
                    Err(Error::InvalidProtocolVersion(format!(
                        "Unsupported SALTO protocol version, major {version}"
                    ))),
                );
                return;
            }
        }

        out.push(Action::Subscribe);
        out.push(Action::Phase(Phase::Authenticating));

        if major == Some(1) {
            self.begin_v0100(out);
        } else {
            self.begin_v0200(out);
        }
    }

    // -- v0200 -------------------------------------------------------------

    fn begin_v0200(&mut self, out: &mut Vec<Action>) {
        // The session mutates the key (opening mode, audit tag), so it works
        // on a copy.
        let mut key = self.key.clone();

        if self.options.mode == Mode::Office {
            key.tags.insert(
                TAG_OPENING_MODE,
                GeneralPurposeTag {
                    tag_id: TAG_OPENING_MODE,
                    permissions: Permissions::new(
                        Permissions::READABLE.flags() | Permissions::READ_WITHOUT_SECURITY.flags(),
                    ),
                    value: vec![Mode::Office as u8],
                },
            );
        }

        let ssp = match self.random.take() {
            Some(random) => SecureProtocolManager::with_random(key.kn_key, random),
            None => SecureProtocolManager::new(key.kn_key),
        };
        let justin = JustinProtocolManager::new_with_key(key);

        self.state = State::V0200(Box::new(V0200 {
            stack: JustinStack0100::new(ssp, justin),
            first_packet: true,
            final_op_result: None,
            exchanging: false,
            traced_kn_refusals: 0,
        }));

        out.push(Action::SetTimer {
            id: TimerId::FirstPacket,
            after_ms: self.options.timeouts.first_packet_ms,
        });
    }

    fn poll_v0200(&mut self, event: Event<'_>, out: &mut Vec<Action>) {
        let State::V0200(session) = &mut self.state else {
            unreachable!("dispatched on the v0200 state")
        };

        match event {
            Event::Notification(packet) => {
                out.push(Action::Trace(Trace::Rx(packet.to_vec())));

                let response = match session.stack.handle_packet(packet) {
                    Ok(response) => response,
                    Err(e) => {
                        self.finish(out, Err(e));
                        return;
                    }
                };

                out.push(Action::Trace(Trace::Tx(response.clone())));

                let refusals = session.stack.justin().refused_kn_reads();
                if refusals > session.traced_kn_refusals {
                    session.traced_kn_refusals = refusals;
                    out.push(info(
                        "Refused to hand out the kN key: the lock asked for tag 0x02 outside a secure session",
                    ));
                }

                out.push(Action::Write(response));

                if !session.exchanging && session.stack.ssp_state() == SspState::InSession {
                    session.exchanging = true;
                    out.push(Action::Phase(Phase::Exchanging));
                }

                // The lock reports its verdict by writing the audit tag; the
                // first one whose group is accepted or rejected is final.
                if session.final_op_result.is_none() {
                    if let Some(op_result) = session.stack.justin().last_audit_op_result() {
                        if OpResultGroup::of(op_result).is_final() {
                            session.final_op_result = Some(op_result);
                        }
                    }
                }

                if session.stack.justin_state() == JustinState::Ready {
                    let op_result = session.final_op_result;
                    self.finish(out, Ok(Outcome::new(2, op_result)));
                    return;
                }

                session.first_packet = false;
                let (id, after_ms) = next_wait(&self.options.timeouts, session);
                out.push(Action::SetTimer { id, after_ms });
            }
            Event::Timer(_) => {
                let (_, waited) = next_wait(&self.options.timeouts, session);

                match session.final_op_result {
                    Some(op_result) => {
                        out.push(info("The lock went silent after reporting its result"));
                        self.finish(out, Ok(Outcome::new(2, Some(op_result))));
                    }
                    None => {
                        out.push(info(format!("No packet from the lock within {waited} ms")));
                        self.finish(out, Err(Error::Timeout(u64::from(waited))));
                    }
                }
            }
            Event::LinkClosed => {
                let op_result = session.final_op_result;
                out.push(info(LOCK_DISCONNECTED_MESSAGE));
                self.finish(out, Ok(Outcome::new(2, op_result)));
            }
            other => self.unexpected(other, "during the v0200 exchange", out),
        }
    }

    // -- v0100 -------------------------------------------------------------

    fn begin_v0100(&mut self, out: &mut Vec<Action>) {
        let mut identify = Vec::with_capacity(1 + self.key.tag_1.len());
        identify.push(v0100_prefix::IDENTIFY);
        identify.extend_from_slice(&self.key.tag_1);

        self.state = State::V0100(V0100 {
            kn_key: self.key.kn_key,
            step: V0100Step::AwaitingNonce,
        });

        out.push(Action::Trace(Trace::Tx(identify.clone())));
        // The lock is expected to receive this frame whole — a long write or a
        // larger MTU, never split across GATT writes.
        out.push(Action::Write(identify));
        out.push(Action::Pause {
            ms: V0100_SETTLE_MS,
        });
        out.push(Action::SetTimer {
            id: TimerId::FirstPacket,
            after_ms: self.options.timeouts.first_packet_ms,
        });
    }

    fn poll_v0100(&mut self, event: Event<'_>, out: &mut Vec<Action>) {
        let State::V0100(session) = &mut self.state else {
            unreachable!("dispatched on the v0100 state")
        };

        match event {
            Event::Notification(packet) => {
                out.push(Action::Trace(Trace::Rx(packet.to_vec())));

                if packet.first().copied() != Some(session.step.expected_prefix()) {
                    // Anything else is noise; the deadline keeps running.
                    out.push(info(format!(
                        "Ignoring an unexpected packet {}",
                        hex::encode(packet)
                    )));
                    return;
                }

                match session.step {
                    V0100Step::AwaitingNonce => {
                        if packet.len() < 1 + V0100_NONCE_LENGTH {
                            self.finish(
                                out,
                                Err(Error::InvalidData(format!(
                                    "v0100 nonce packet too short: {} bytes",
                                    packet.len()
                                ))),
                            );
                            return;
                        }

                        let signed = encrypt_aes_cbc(
                            &session.kn_key,
                            &V0100_SIGN_IV,
                            &packet[1..1 + V0100_NONCE_LENGTH],
                        );
                        let mut signed_packet = Vec::with_capacity(1 + signed.len());
                        signed_packet.push(v0100_prefix::SIGNED_NONCE);
                        signed_packet.extend_from_slice(&signed);

                        session.step = V0100Step::AwaitingResult;

                        out.push(Action::Phase(Phase::Exchanging));
                        out.push(Action::Trace(Trace::Tx(signed_packet.clone())));
                        out.push(Action::Write(signed_packet));
                        out.push(Action::SetTimer {
                            id: TimerId::Packet,
                            after_ms: self.options.timeouts.packet_ms,
                        });
                    }
                    V0100Step::AwaitingResult => {
                        if packet.len() < 2 {
                            self.finish(
                                out,
                                Err(Error::InvalidData(format!(
                                    "v0100 result packet too short: {} bytes",
                                    packet.len()
                                ))),
                            );
                            return;
                        }

                        self.finish(out, Ok(Outcome::new(1, Some(packet[1]))));
                    }
                }
            }
            Event::Timer(_) => {
                let prefix = session.step.expected_prefix();
                let waited = match session.step {
                    V0100Step::AwaitingNonce => self.options.timeouts.first_packet_ms,
                    V0100Step::AwaitingResult => self.options.timeouts.packet_ms,
                };

                out.push(info(format!(
                    "No 0x{prefix:02X} packet from the lock within {waited} ms"
                )));
                self.finish(out, Err(Error::Timeout(u64::from(waited))));
            }
            Event::LinkClosed => self.finish(out, Err(Error::Disconnected)),
            other => self.unexpected(other, "during the v0100 exchange", out),
        }
    }

    // -- shared ------------------------------------------------------------

    fn finish(&mut self, out: &mut Vec<Action>, result: Result<Outcome, Error>) {
        out.push(Action::Phase(Phase::Finished));
        out.push(Action::Done(result));
        self.finished = true;
    }

    /// An event the contract says cannot happen here. That is a bug in the
    /// shell, so it ends the session loudly rather than being swallowed.
    fn unexpected(&mut self, event: Event<'_>, when: &str, out: &mut Vec<Action>) {
        self.finish(
            out,
            Err(Error::InvalidState {
                expected: format!("no {} {when}", describe(&event)),
                actual: format!("{} {when}", describe(&event)),
            }),
        );
    }
}

/// Which wait comes next, and how long it is.
fn next_wait(timeouts: &Timeouts, session: &V0200) -> (TimerId, u32) {
    if session.final_op_result.is_some() {
        return (TimerId::AfterFinalResult, timeouts.after_final_result_ms);
    }

    if session.first_packet {
        (TimerId::FirstPacket, timeouts.first_packet_ms)
    } else {
        (TimerId::Packet, timeouts.packet_ms)
    }
}

fn info(message: impl Into<String>) -> Action {
    Action::Trace(Trace::Info(message.into()))
}

fn describe(event: &Event<'_>) -> &'static str {
    match event {
        Event::Started => "a start",
        Event::ProtocolInfo(_) => "protocol info",
        Event::Notification(_) => "a notification",
        Event::Timer(_) => "a timer",
        Event::LinkClosed => "a disconnect",
        Event::Aborted => "an abort",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkey_core::security::random::FixedRandom;

    const RANDOM_B: [u8; 16] = [0xB0; 16];

    fn key() -> MobileKey {
        MobileKey::new([0x42; 16])
    }

    fn session(detection: Detection) -> Session {
        Session::with_random(
            key(),
            Options {
                detection,
                ..Options::default()
            },
            Box::new(FixedRandom::single(RANDOM_B)),
        )
    }

    /// A compact, comparable shape for one action.
    fn shape(action: &Action) -> String {
        match action {
            Action::AnnounceAppProtocol => "announce".to_string(),
            Action::ReadProtocolInfo { timeout_ms } => format!("read({timeout_ms})"),
            Action::Subscribe => "subscribe".to_string(),
            Action::Write(bytes) => format!("write({})", hex::encode(bytes)),
            Action::Pause { ms } => format!("pause({ms})"),
            Action::SetTimer { id, after_ms } => format!("timer({id:?},{after_ms})"),
            Action::Phase(phase) => format!("phase({phase})"),
            Action::Trace(Trace::Rx(bytes)) => format!("rx({})", hex::encode(bytes)),
            Action::Trace(Trace::Tx(bytes)) => format!("tx({})", hex::encode(bytes)),
            Action::Trace(Trace::Read(bytes)) => format!("read-trace({})", hex::encode(bytes)),
            Action::Trace(Trace::Info(_)) => "info".to_string(),
            Action::Done(Ok(outcome)) => format!("done(ok,{:?})", outcome.op_result),
            Action::Done(Err(e)) => format!("done(err,{})", e.code()),
        }
    }

    fn shapes(actions: &[Action]) -> Vec<String> {
        actions.iter().map(shape).collect()
    }

    /// Everything that is not a trace, which is where the decisions show.
    fn decisions(actions: &[Action]) -> Vec<String> {
        actions
            .iter()
            .filter(|a| !matches!(a, Action::Trace(_)))
            .map(shape)
            .collect()
    }

    fn done(actions: &[Action]) -> Option<&Result<Outcome, Error>> {
        actions.iter().find_map(|a| match a {
            Action::Done(result) => Some(result),
            _ => None,
        })
    }

    // -- detection ---------------------------------------------------------

    #[test]
    fn app_protocol_announces_then_reads() {
        let mut session = session(Detection::AppProtocol);

        assert_eq!(
            shapes(&session.poll(Event::Started)),
            ["phase(detecting-version)", "announce", "read(1000)"]
        );
    }

    #[test]
    fn read_only_never_announces() {
        let mut session = session(Detection::ReadOnly);

        assert_eq!(
            shapes(&session.poll(Event::Started)),
            ["phase(detecting-version)", "read(1000)"]
        );
    }

    #[test]
    fn none_asks_nothing_and_runs_v0200() {
        let mut session = session(Detection::None);

        assert_eq!(
            decisions(&session.poll(Event::Started)),
            [
                "phase(detecting-version)",
                "subscribe",
                "phase(authenticating)",
                "timer(FirstPacket,30000)"
            ]
        );
    }

    #[test]
    fn an_unreadable_notify_characteristic_skips_the_read() {
        let mut session = Session::new(
            key(),
            Options {
                notify_readable: false,
                ..Options::default()
            },
        );

        let actions = session.poll(Event::Started);

        assert!(
            !shapes(&actions).iter().any(|a| a.starts_with("read")),
            "nothing may be read from a characteristic that cannot be read"
        );
        assert!(decisions(&actions).contains(&"subscribe".to_string()));
    }

    #[test]
    fn major_one_runs_the_v0100_handshake() {
        let mut session = session(Detection::ReadOnly);
        session.poll(Event::Started);

        let actions = session.poll(Event::ProtocolInfo(Some(&[0x01, 0x00, 0x01])));
        let identify = {
            let mut bytes = vec![0x02];
            bytes.extend_from_slice(&key().tag_1);
            hex::encode(bytes)
        };

        assert_eq!(
            decisions(&actions),
            vec![
                "subscribe".to_string(),
                "phase(authenticating)".to_string(),
                format!("write({identify})"),
                "pause(50)".to_string(),
                "timer(FirstPacket,30000)".to_string(),
            ]
        );
    }

    #[test]
    fn an_unknown_major_is_the_one_fatal_detection_outcome() {
        let mut session = session(Detection::ReadOnly);
        session.poll(Event::Started);

        let actions = session.poll(Event::ProtocolInfo(Some(&[0x01, 0x00, 0x03])));

        assert!(matches!(
            done(&actions),
            Some(Err(Error::InvalidProtocolVersion(_)))
        ));
    }

    #[test]
    fn a_failed_read_and_an_odd_shape_both_mean_v0200() {
        for info in [
            None,
            Some(&[][..]),
            Some(&[0x01, 0x00][..]),
            Some(&[0x02, 0x00, 0x01][..]),
        ] {
            let mut session = session(Detection::ReadOnly);
            session.poll(Event::Started);

            let actions = session.poll(Event::ProtocolInfo(info));

            assert_eq!(
                decisions(&actions),
                [
                    "subscribe",
                    "phase(authenticating)",
                    "timer(FirstPacket,30000)"
                ],
                "protocol info {info:02X?} should have left the version unknown"
            );
        }
    }

    // -- v0200 -------------------------------------------------------------

    /// Drive a session to the point where the lock may speak.
    fn started_v0200() -> Session {
        let mut session = session(Detection::None);
        session.poll(Event::Started);
        session
    }

    #[test]
    fn the_first_packet_gets_thirty_seconds_and_the_rest_get_ten() {
        let mut session = started_v0200();

        // The lock opens the SSP handshake; the phone answers and re-arms.
        let actions = session.poll(Event::Notification(&[0x01, 0x01]));

        assert!(
            decisions(&actions)
                .iter()
                .any(|a| a == "timer(Packet,10000)"),
            "after the first packet the wait drops to the packet timeout"
        );
    }

    #[test]
    fn a_timeout_before_any_result_is_a_failure() {
        let mut session = started_v0200();

        let actions = session.poll(Event::Timer(TimerId::FirstPacket));

        assert!(matches!(done(&actions), Some(Err(Error::Timeout(30000)))));
    }

    #[test]
    fn a_disconnect_ends_the_v0200_session_without_a_result() {
        let mut session = started_v0200();

        let actions = session.poll(Event::LinkClosed);

        match done(&actions) {
            Some(Ok(outcome)) => {
                assert_eq!(outcome.op_result, None);
                assert_eq!(outcome.protocol_version, 2);
                assert!(!outcome.accepted);
            }
            other => panic!("expected a result, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_packet_ends_the_session_with_its_own_error() {
        let mut session = started_v0200();

        let actions = session.poll(Event::Notification(&[0x01]));

        assert!(matches!(done(&actions), Some(Err(Error::InvalidData(_)))));
    }

    // -- v0100 -------------------------------------------------------------

    fn started_v0100() -> Session {
        let mut session = session(Detection::ReadOnly);
        session.poll(Event::Started);
        session.poll(Event::ProtocolInfo(Some(&[0x01, 0x00, 0x01])));
        session
    }

    #[test]
    fn v0100_ignores_a_packet_it_is_not_waiting_for_without_rearming() {
        let mut session = started_v0100();

        let actions = session.poll(Event::Notification(&[0xFF, 0x00]));

        assert_eq!(
            decisions(&actions),
            Vec::<String>::new(),
            "noise must not restart the deadline"
        );
    }

    #[test]
    fn v0100_signs_the_nonce_and_waits_for_the_result() {
        let mut session = started_v0100();
        let mut nonce = vec![0x03];
        nonce.extend_from_slice(&[0x11; 16]);

        let actions = session.poll(Event::Notification(&nonce));
        let written = actions.iter().find_map(|a| match a {
            Action::Write(bytes) => Some(bytes.clone()),
            _ => None,
        });

        let signed = written.expect("the signed nonce is written");
        assert_eq!(signed[0], 0x04);
        assert_eq!(signed.len(), 1 + 16);
        assert!(decisions(&actions).contains(&"timer(Packet,10000)".to_string()));

        let actions = session.poll(Event::Notification(&[0x05, 30]));
        match done(&actions) {
            Some(Ok(outcome)) => {
                assert_eq!(outcome.op_result, Some(30));
                assert_eq!(outcome.protocol_version, 1);
                assert!(outcome.accepted);
                assert_eq!(outcome.op_result_name(), "KEY_PROCESSED");
            }
            other => panic!("expected a result, got {other:?}"),
        }
    }

    #[test]
    fn v0100_rejects_a_truncated_nonce() {
        let mut session = started_v0100();

        let actions = session.poll(Event::Notification(&[0x03, 0x11, 0x22]));

        assert!(matches!(done(&actions), Some(Err(Error::InvalidData(_)))));
    }

    #[test]
    fn a_disconnect_during_v0100_is_a_failure() {
        let mut session = started_v0100();

        let actions = session.poll(Event::LinkClosed);

        assert!(matches!(done(&actions), Some(Err(Error::Disconnected))));
    }

    // -- lifecycle ---------------------------------------------------------

    #[test]
    fn an_abort_ends_the_session_wherever_it_is() {
        let mut session = started_v0200();

        let actions = session.poll(Event::Aborted);

        assert!(matches!(done(&actions), Some(Err(Error::Cancelled))));
        assert!(session.is_finished());
    }

    #[test]
    fn a_finished_session_answers_nothing() {
        let mut session = started_v0200();
        session.poll(Event::Aborted);

        assert!(session.poll(Event::Notification(&[0x01, 0x01])).is_empty());
        assert!(session.poll(Event::LinkClosed).is_empty());
    }

    #[test]
    fn every_exit_path_reports_the_finished_phase() {
        let cases: Vec<Box<dyn Fn() -> Vec<Action>>> = vec![
            Box::new(|| started_v0200().poll(Event::Aborted)),
            Box::new(|| started_v0200().poll(Event::LinkClosed)),
            Box::new(|| started_v0200().poll(Event::Timer(TimerId::FirstPacket))),
            Box::new(|| started_v0100().poll(Event::LinkClosed)),
        ];

        for run in cases {
            let actions = run();

            assert!(
                shapes(&actions).contains(&"phase(finished)".to_string()),
                "the caller must always learn that the session is over"
            );
        }
    }
}
