//! The native session driver: connect to a lock, then run one opening attempt.
//!
//! All the decisions live in [`mkey_session::Session`]; this holds the link,
//! the key and enough state to keep the call sequence honest.

use crate::pump::{run_session, SessionObserver};
use crate::traits::{BleTransport, ConnectedLock, DiscoveredLock, LockFilter};
#[cfg(feature = "btleplug")]
use crate::BtleplugTransport;
use mkey_core::data::mobile_key::MobileKey;
use mkey_core::security::random::RandomSource;
use mkey_core::Error;
use mkey_session::{Detection, Mode, Options, Outcome, Phase, Session, Timeouts, Trace};
use std::time::Duration;

/// Opening mode for the lock operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpeningMode {
    /// Standard mode - normal open/close.
    #[default]
    Standard,
    /// Office mode - toggle office/latch state (door stays unlocked).
    Office,
}

impl From<OpeningMode> for Mode {
    fn from(mode: OpeningMode) -> Self {
        match mode {
            OpeningMode::Standard => Mode::Standard,
            OpeningMode::Office => Mode::Office,
        }
    }
}

const DEFAULT_SCAN_DURATION: Duration = Duration::from_secs(5);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// How the version handshake is chosen for a given lock.
///
/// [`mkey_session::Detection`] is the session's three-way choice. This adds
/// the one decision that needs an advertisement, which the session never sees
/// — the same split the browser port makes between `handshake-plan.ts` and the
/// session's own `VersionDetection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandshakePlan {
    /// Pick from the advertisement: a lock that advertises a SALTO
    /// manufacturer record is announced to, a lock recognised by its service
    /// UUID alone is only read. This is the rule mkey-rs has always followed
    /// on hardware, and one real lock needs it — it acknowledges the app
    /// protocol write and then kills the link on the read that follows.
    #[default]
    Auto,
    /// Always announce the app protocol first.
    AppProtocol,
    /// Never announce it; read the protocol info only.
    ReadOnly,
    /// Ask nothing at all: subscribe straight away, version unknown.
    None,
}

impl HandshakePlan {
    /// What [`HandshakePlan::Auto`] resolves to for a given advertised version.
    ///
    /// `0` means the lock was recognised by its service UUID alone, i.e. it
    /// carried no SALTO manufacturer record.
    pub fn for_advertised_version(advertised_version: u8) -> Detection {
        if advertised_version == 0 {
            Detection::ReadOnly
        } else {
            Detection::AppProtocol
        }
    }

    /// The session-level mode this plan means for a given lock.
    pub fn resolve(self, advertised_version: u8) -> Detection {
        match self {
            Self::Auto => Self::for_advertised_version(advertised_version),
            Self::AppProtocol => Detection::AppProtocol,
            Self::ReadOnly => Detection::ReadOnly,
            Self::None => Detection::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    Disconnected,
    Connected,
    Authenticated,
}

impl std::fmt::Display for LockState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockState::Disconnected => write!(f, "DISCONNECTED"),
            LockState::Connected => write!(f, "CONNECTED"),
            LockState::Authenticated => write!(f, "AUTHENTICATED"),
        }
    }
}

/// Writes every phase and packet to stderr.
///
/// What this crate always did, now optional and replaceable.
#[derive(Debug, Clone, Copy, Default)]
pub struct StderrObserver;

impl SessionObserver for StderrObserver {
    fn phase(&mut self, phase: Phase) {
        eprintln!("[PHASE] {phase}");
    }

    fn trace(&mut self, trace: &Trace) {
        match trace {
            Trace::Rx(bytes) => eprintln!("[RX] {}", hex::encode(bytes)),
            Trace::Tx(bytes) => eprintln!("[TX] {}", hex::encode(bytes)),
            Trace::Read(bytes) => eprintln!("[READ] {}", hex::encode(bytes)),
            Trace::Info(message) => eprintln!("[INFO] {message}"),
        }
    }
}

/// The phone side of a SALTO session, over any [`BleTransport`].
///
/// The transport is a type parameter so the same driver runs against btleplug
/// on a desktop and against an in-process simulator in the tests.
pub struct SaltoLock<T: BleTransport> {
    transport: T,
    connected_lock: Option<ConnectedLock>,
    mobile_key: Option<MobileKey>,
    state: LockState,
    handshake: HandshakePlan,
    timeouts: Timeouts,
    random: Option<Box<dyn RandomSource + Send>>,
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
            mobile_key: None,
            state: LockState::Disconnected,
            handshake: HandshakePlan::default(),
            timeouts: Timeouts::default(),
            random: None,
        }
    }

    /// Choose how the protocol version is worked out. Defaults to
    /// [`HandshakePlan::Auto`].
    pub fn with_handshake(mut self, handshake: HandshakePlan) -> Self {
        self.handshake = handshake;
        self
    }

    /// Choose how the protocol version is worked out, after construction.
    pub fn set_handshake(&mut self, handshake: HandshakePlan) {
        self.handshake = handshake;
    }

    /// Override the step timeouts. Defaults to [`Timeouts::default`].
    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Replace the source of `RandomB` with a deterministic one.
    ///
    /// Test tooling: it makes a whole session reproducible byte for byte.
    pub fn with_random(mut self, random: Box<dyn RandomSource + Send>) -> Self {
        self.random = Some(random);
        self
    }

    /// The transport underneath, for what only it can report.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn state(&self) -> LockState {
        self.state
    }

    /// Scan for SALTO locks without connecting.
    pub async fn scan(&self, duration: Option<Duration>) -> Result<Vec<DiscoveredLock>, Error> {
        self.transport
            .scan(duration.unwrap_or(DEFAULT_SCAN_DURATION))
            .await
    }

    /// Scan for a SALTO lock and connect to the first one found.
    pub async fn scan_and_connect(
        &mut self,
        timeout: Option<Duration>,
    ) -> Result<&DiscoveredLock, Error> {
        self.scan_and_connect_filtered(timeout, None).await
    }

    /// Scan for a SALTO lock matching the filter and connect immediately.
    pub async fn scan_and_connect_filtered(
        &mut self,
        timeout: Option<Duration>,
        filter: Option<LockFilter>,
    ) -> Result<&DiscoveredLock, Error> {
        self.expect_state(LockState::Disconnected)?;

        let timeout = timeout.unwrap_or(DEFAULT_SCAN_DURATION);
        let connected = self.transport.scan_and_connect(timeout, filter).await?;

        Ok(self.after_connect(connected))
    }

    /// Connect to a previously discovered lock by its ID.
    ///
    /// Use this for the "user picks from a list" workflow: [`SaltoLock::scan`],
    /// then let the user choose, then connect to the chosen id.
    pub async fn connect_by_id(
        &mut self,
        lock_id: &str,
        timeout: Option<Duration>,
    ) -> Result<&DiscoveredLock, Error> {
        self.expect_state(LockState::Disconnected)?;

        let timeout = timeout.unwrap_or(DEFAULT_TIMEOUT);
        let connected = self.transport.connect_by_id(lock_id, timeout).await?;

        Ok(self.after_connect(connected))
    }

    /// Information about the currently connected lock.
    ///
    /// `protocol_version` is whatever the advertisement claimed. The version
    /// the lock actually speaks is settled during the opening attempt and
    /// reported in [`Outcome::protocol_version`].
    pub fn connected_lock(&self) -> Option<&DiscoveredLock> {
        self.connected_lock.as_ref().map(|c| &c.info)
    }

    /// Load the mobile key this session will use.
    pub async fn authenticate(&mut self, mobile_key: MobileKey) -> Result<(), Error> {
        self.expect_state(LockState::Connected)?;

        self.mobile_key = Some(mobile_key);
        self.state = LockState::Authenticated;
        Ok(())
    }

    /// Open the lock in standard mode.
    pub async fn open(&mut self) -> Result<Outcome, Error> {
        self.open_with_mode(OpeningMode::Standard).await
    }

    /// Toggle office mode (the door stays unlocked until toggled again).
    pub async fn open_office(&mut self) -> Result<Outcome, Error> {
        self.open_with_mode(OpeningMode::Office).await
    }

    /// Open the lock, reporting progress to stderr.
    pub async fn open_with_mode(&mut self, mode: OpeningMode) -> Result<Outcome, Error> {
        self.open_observed(mode, &mut StderrObserver).await
    }

    /// Open the lock, reporting progress to `observer`.
    ///
    /// The link is disconnected before this returns, on every path.
    pub async fn open_observed<O: SessionObserver>(
        &mut self,
        mode: OpeningMode,
        observer: &mut O,
    ) -> Result<Outcome, Error> {
        self.expect_state(LockState::Authenticated)?;

        let key = self.mobile_key.clone().ok_or(Error::InvalidMobileKey)?;
        let advertised = self
            .connected_lock
            .as_ref()
            .map(|c| c.info.protocol_version)
            .unwrap_or(0);

        let options = Options {
            mode: mode.into(),
            detection: self.handshake.resolve(advertised),
            timeouts: self.timeouts,
            notify_readable: self.transport.notify_readable(),
        };

        let mut session = match self.random.take() {
            Some(random) => Session::with_random(key, options, random),
            None => Session::new(key, options),
        };

        let result = run_session(&mut self.transport, &mut session, observer).await;

        // `run_session` owns the teardown, so the link is down either way.
        self.connected_lock = None;
        self.state = LockState::Disconnected;

        result
    }

    /// Read a tag out of the loaded mobile key.
    pub fn read_tag(&self, tag_id: u8) -> Result<Vec<u8>, Error> {
        let key = self.mobile_key.as_ref().ok_or(Error::InvalidMobileKey)?;

        key.get_tag(tag_id)
            .map(|tag| tag.data)
            .ok_or_else(|| Error::KeyNotFound(format!("Tag 0x{tag_id:02X}")))
    }

    /// Set a tag on the loaded mobile key, before the session starts.
    pub fn write_tag(&mut self, tag_id: u8, data: &[u8]) -> Result<(), Error> {
        let key = self.mobile_key.as_mut().ok_or(Error::InvalidMobileKey)?;

        key.set_tag_data(tag_id, data.to_vec());
        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<(), Error> {
        self.transport.disconnect().await?;
        self.connected_lock = None;
        self.mobile_key = None;
        self.state = LockState::Disconnected;
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }

    fn after_connect(&mut self, connected: ConnectedLock) -> &DiscoveredLock {
        self.connected_lock = Some(connected);
        self.mobile_key = None;
        self.state = LockState::Connected;

        &self.connected_lock.as_ref().expect("just stored").info
    }

    fn expect_state(&self, expected: LockState) -> Result<(), Error> {
        if self.state == expected {
            return Ok(());
        }

        Err(Error::InvalidState {
            expected: expected.to_string(),
            actual: self.state.to_string(),
        })
    }
}
