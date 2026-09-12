//! Driving a [`Session`] over a [`BleTransport`].
//!
//! The session decides; this decides nothing. Every branch here is either "do
//! what the action says" or "turn what the radio did into an event". Keeping
//! it that thin is what makes it worth having a second one in TypeScript.

use std::time::Duration;

use mkey_session::{
    Action, Error, Event, Outcome, Phase, Session, TimerId, Trace, APP_PROTOCOL_REQUEST,
};
use tokio::time::{sleep, timeout, Instant};

use crate::traits::BleTransport;

/// Somewhere to report progress. Every method is optional.
pub trait SessionObserver {
    /// How far along the attempt is. `finished` arrives on every exit path.
    fn phase(&mut self, _phase: Phase) {}

    /// One observation: a packet in either direction, or a note.
    fn trace(&mut self, _trace: &Trace) {}
}

/// Report nothing.
impl SessionObserver for () {}

/// An event the pump holds while it hands a borrowed view to the session.
enum Pending {
    Started,
    ProtocolInfo(Option<Vec<u8>>),
    Notification(Vec<u8>),
    Timer(TimerId),
    LinkClosed,
}

impl Pending {
    fn as_event(&self) -> Event<'_> {
        match self {
            Self::Started => Event::Started,
            Self::ProtocolInfo(info) => Event::ProtocolInfo(info.as_deref()),
            Self::Notification(packet) => Event::Notification(packet),
            Self::Timer(id) => Event::Timer(*id),
            Self::LinkClosed => Event::LinkClosed,
        }
    }
}

/// Run one opening attempt to completion.
///
/// The link is disconnected before this returns, on every path — success, a
/// protocol failure, a timeout, a transport failure. [`Phase::Finished`] is
/// reported just before that teardown, failures included.
pub async fn run_session<T, O>(
    transport: &mut T,
    session: &mut Session,
    observer: &mut O,
) -> Result<Outcome, Error>
where
    T: BleTransport,
    O: SessionObserver,
{
    let result = pump(transport, session, observer).await;

    // A transport failure never reaches the session, so it never got to report
    // the last phase itself.
    if !session.is_finished() {
        observer.phase(Phase::Finished);
    }

    let _ = transport.disconnect().await;

    result
}

async fn pump<T, O>(
    transport: &mut T,
    session: &mut Session,
    observer: &mut O,
) -> Result<Outcome, Error>
where
    T: BleTransport,
    O: SessionObserver,
{
    let mut pending = Pending::Started;
    // At most one timer is ever armed, and an unexpected packet must not push
    // its deadline out — so the deadline is remembered, not the duration.
    let mut deadline: Option<(TimerId, Instant)> = None;

    loop {
        let actions = session.poll(pending.as_event());
        let mut protocol_info: Option<Option<Vec<u8>>> = None;

        for action in actions {
            match action {
                Action::AnnounceAppProtocol => {
                    // Not fatal: one real lock acknowledges this and then drops
                    // the link on the read that follows.
                    let note = match transport.write(&APP_PROTOCOL_REQUEST).await {
                        Ok(()) => format!(
                            "Wrote the app protocol request {}",
                            hex::encode(APP_PROTOCOL_REQUEST)
                        ),
                        Err(e) => format!("App protocol request failed: {e}"),
                    };
                    observer.trace(&Trace::Info(note));
                }
                Action::ReadProtocolInfo { timeout_ms } => {
                    let read = timeout(
                        Duration::from_millis(u64::from(timeout_ms)),
                        transport.read_notify_value(),
                    )
                    .await;

                    protocol_info = Some(match read {
                        Ok(Ok(info)) => Some(info),
                        Ok(Err(e)) => {
                            observer.trace(&Trace::Info(format!("Protocol info read failed: {e}")));
                            None
                        }
                        Err(_) => {
                            observer.trace(&Trace::Info(format!(
                                "No protocol info within {timeout_ms} ms"
                            )));
                            None
                        }
                    });
                }
                Action::Subscribe => transport.subscribe().await?,
                Action::Write(bytes) => transport.write(&bytes).await?,
                Action::Pause { ms } => sleep(Duration::from_millis(u64::from(ms))).await,
                Action::SetTimer { id, after_ms } => {
                    deadline = Some((
                        id,
                        Instant::now() + Duration::from_millis(u64::from(after_ms)),
                    ));
                }
                Action::Phase(phase) => observer.phase(phase),
                Action::Trace(trace) => observer.trace(&trace),
                Action::Done(result) => return result,
            }
        }

        if let Some(info) = protocol_info {
            pending = Pending::ProtocolInfo(info);
            continue;
        }

        let Some((id, at)) = deadline else {
            return Err(Error::InvalidState {
                expected: "a pending wait or a finished session".to_string(),
                actual: "the session asked for nothing and did not finish".to_string(),
            });
        };

        pending = match tokio::time::timeout_at(at, transport.receive()).await {
            Ok(Ok(Some(notification))) => Pending::Notification(notification.data),
            Ok(Ok(None)) => Pending::LinkClosed,
            Ok(Err(e)) => {
                // The link is gone. The session is told what happened, not how.
                observer.trace(&Trace::Info(format!("The link failed: {e}")));
                Pending::LinkClosed
            }
            Err(_) => Pending::Timer(id),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{ConnectedLock, DiscoveredLock, LockFilter, Notification};
    use mkey_core::MobileKey;
    use mkey_session::{Detection, Options};

    /// What the fake lock does when the protocol info is read.
    enum ProtocolInfo {
        Value(Vec<u8>),
        /// Fail the read, as a lock that dropped the link would.
        Fails,
        /// Never answer, so the read has to time out.
        Silent,
    }

    /// A lock that answers the handshake and then says nothing.
    ///
    /// Everything the pump does before the exchange is observable here: which
    /// bytes were written, how many reads and subscribes happened.
    struct FakeLock {
        notify_readable: bool,
        protocol_info: ProtocolInfo,
        write_fails: bool,
        writes: Vec<Vec<u8>>,
        reads: usize,
        subscribes: usize,
        disconnects: usize,
    }

    impl FakeLock {
        fn answering(major: u8) -> Self {
            Self {
                notify_readable: true,
                protocol_info: ProtocolInfo::Value(vec![0x01, 0x00, major]),
                write_fails: false,
                writes: Vec::new(),
                reads: 0,
                subscribes: 0,
                disconnects: 0,
            }
        }
    }

    impl BleTransport for FakeLock {
        async fn scan(&self, _duration: Duration) -> Result<Vec<DiscoveredLock>, Error> {
            unimplemented!("the pump never scans")
        }

        async fn scan_and_connect(
            &mut self,
            _timeout: Duration,
            _filter: Option<LockFilter>,
        ) -> Result<ConnectedLock, Error> {
            unimplemented!("the pump never scans")
        }

        async fn connect_by_id(
            &mut self,
            _lock_id: &str,
            _timeout: Duration,
        ) -> Result<ConnectedLock, Error> {
            unimplemented!("the pump never connects")
        }

        async fn disconnect(&mut self) -> Result<(), Error> {
            self.disconnects += 1;
            Ok(())
        }

        fn is_connected(&self) -> bool {
            true
        }

        async fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.writes.push(data.to_vec());

            if self.write_fails {
                return Err(Error::GattOperationFailed("Writing failed".to_string()));
            }

            Ok(())
        }

        async fn receive(&mut self) -> Result<Option<Notification>, Error> {
            // The fake lock never drives an exchange; it just goes quiet.
            std::future::pending().await
        }

        async fn subscribe(&mut self) -> Result<(), Error> {
            self.subscribes += 1;
            Ok(())
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

    /// Run a session against the fake lock and report what it saw.
    async fn run(mut lock: FakeLock, detection: Detection) -> (FakeLock, Result<Outcome, Error>) {
        let mut session = Session::new(
            MobileKey::new([0x42; 16]),
            Options {
                detection,
                notify_readable: lock.notify_readable(),
                ..Options::default()
            },
        );

        let result = run_session(&mut lock, &mut session, &mut ()).await;

        (lock, result)
    }

    #[tokio::test(start_paused = true)]
    async fn the_app_protocol_request_goes_out_before_the_read() {
        let (lock, _) = run(FakeLock::answering(2), Detection::AppProtocol).await;

        assert_eq!(
            lock.writes.first().map(Vec::as_slice),
            Some(&[0xC0u8, 0x01, 0x01][..])
        );
        assert_eq!(lock.reads, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_app_protocol_request_is_not_fatal() {
        let mut lock = FakeLock::answering(2);
        lock.write_fails = true;

        let (lock, result) = run(lock, Detection::AppProtocol).await;

        assert_eq!(lock.reads, 1, "the read still happens");
        assert_eq!(lock.subscribes, 1, "the session still starts");
        assert!(
            matches!(result, Err(Error::Timeout(_))),
            "it ends on the silent lock, not on the write: {result:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_read_leaves_the_session_running() {
        let mut lock = FakeLock::answering(2);
        lock.protocol_info = ProtocolInfo::Fails;

        let (lock, result) = run(lock, Detection::ReadOnly).await;

        assert_eq!(lock.reads, 1);
        assert_eq!(lock.subscribes, 1);
        assert!(matches!(result, Err(Error::Timeout(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_read_times_out_and_the_session_carries_on() {
        let mut lock = FakeLock::answering(2);
        lock.protocol_info = ProtocolInfo::Silent;

        let (lock, result) = run(lock, Detection::ReadOnly).await;

        assert_eq!(lock.subscribes, 1);
        assert!(matches!(result, Err(Error::Timeout(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_asked_of_a_lock_whose_notify_cannot_be_read() {
        let mut lock = FakeLock::answering(2);
        lock.notify_readable = false;

        let (lock, _) = run(lock, Detection::AppProtocol).await;

        assert!(lock.writes.is_empty());
        assert_eq!(lock.reads, 0);
        assert_eq!(lock.subscribes, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_link_is_torn_down_on_every_path() {
        for detection in [Detection::AppProtocol, Detection::ReadOnly, Detection::None] {
            let (lock, _) = run(FakeLock::answering(2), detection).await;

            assert_eq!(lock.disconnects, 1, "{detection:?} left the link up");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_finished_phase_is_reported_even_when_the_transport_fails() {
        struct Phases(Vec<Phase>);

        impl SessionObserver for Phases {
            fn phase(&mut self, phase: Phase) {
                self.0.push(phase);
            }
        }

        let mut lock = FakeLock::answering(1);
        // The v0100 flow writes first; failing that write ends the attempt
        // inside the pump, where the session never gets to report a phase.
        lock.write_fails = true;

        let mut session = Session::new(
            MobileKey::new([0x42; 16]),
            Options {
                detection: Detection::ReadOnly,
                ..Options::default()
            },
        );
        let mut phases = Phases(Vec::new());

        let result = run_session(&mut lock, &mut session, &mut phases).await;

        assert!(matches!(result, Err(Error::GattOperationFailed(_))));
        assert_eq!(phases.0.last(), Some(&Phase::Finished));
        assert_eq!(lock.disconnects, 1);
    }
}
