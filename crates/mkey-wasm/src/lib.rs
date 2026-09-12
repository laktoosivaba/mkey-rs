//! The SALTO KS session, compiled for the browser.
//!
//! This is a translation layer and nothing else: it turns JavaScript calls
//! into [`mkey_session::Event`]s and the resulting actions into plain objects.
//! No future crosses the boundary, no callback, no trait — which is what keeps
//! the browser side debuggable: a stack trace stays in one language.
//!
//! ```js
//! import init, { Session } from './mkey_wasm.js';
//!
//! await init();
//!
//! const session = new Session(keyTlv, { detection: 'read-only' });
//!
//! for (const action of session.started()) {
//!   // ... carry it out, then feed the next event
//! }
//! ```

mod wire;

use mkey_core::security::random::FixedRandom;
use mkey_core::MobileKey;
use mkey_session::{Detection, Event, Mode, Options, Timeouts};
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::Serializer;
use wasm_bindgen::prelude::*;

use crate::wire::{parse_timer_id, WireAction};

/// What the caller may set when starting a session. Every field is optional.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct JsOptions {
    /// `"standard"` or `"office"`.
    mode: Option<String>,
    /// `"app-protocol"`, `"read-only"` or `"none"`.
    detection: Option<String>,
    protocol_info_read_ms: Option<u32>,
    first_packet_ms: Option<u32>,
    packet_ms: Option<u32>,
    after_final_result_ms: Option<u32>,
    notify_readable: Option<bool>,
    /// Fixed `RandomB` values, in order.
    ///
    /// Test tooling — it is what makes replaying a recorded exchange possible.
    /// Left out, the session draws from the platform CSPRNG.
    random: Option<Vec<serde_bytes::ByteBuf>>,
}

impl JsOptions {
    fn into_options(self) -> Result<Options, JsValue> {
        let defaults = Timeouts::default();

        Ok(Options {
            mode: match self.mode.as_deref() {
                None | Some("standard") => Mode::Standard,
                Some("office") => Mode::Office,
                Some(other) => return Err(js_error(&format!("unknown opening mode {other}"))),
            },
            detection: match self.detection.as_deref() {
                None | Some("app-protocol") => Detection::AppProtocol,
                Some("read-only") => Detection::ReadOnly,
                Some("none") => Detection::None,
                Some(other) => return Err(js_error(&format!("unknown detection mode {other}"))),
            },
            timeouts: Timeouts {
                protocol_info_read_ms: self
                    .protocol_info_read_ms
                    .unwrap_or(defaults.protocol_info_read_ms),
                first_packet_ms: self.first_packet_ms.unwrap_or(defaults.first_packet_ms),
                packet_ms: self.packet_ms.unwrap_or(defaults.packet_ms),
                after_final_result_ms: self
                    .after_final_result_ms
                    .unwrap_or(defaults.after_final_result_ms),
            },
            notify_readable: self.notify_readable.unwrap_or(true),
        })
    }
}

/// One opening attempt.
///
/// Every method feeds the session one event and returns the array of actions
/// the caller must carry out, in order. After an action of type `done`, feed
/// it nothing more.
#[wasm_bindgen]
pub struct Session {
    inner: mkey_session::Session,
}

#[wasm_bindgen]
impl Session {
    /// Build a session from a mobile key in its TLV encoding.
    #[wasm_bindgen(constructor)]
    pub fn new(mobile_key_tlv: &[u8], options: JsValue) -> Result<Session, JsValue> {
        let key = MobileKey::from_bytes(mobile_key_tlv).map_err(|e| js_error(&e.to_string()))?;

        let mut options: JsOptions = if options.is_undefined() || options.is_null() {
            JsOptions::default()
        } else {
            serde_wasm_bindgen::from_value(options)?
        };

        let random = options.random.take();
        let options = options.into_options()?;

        let inner = match random {
            Some(values) => {
                let values = values
                    .into_iter()
                    .map(|value| {
                        <[u8; 16]>::try_from(value.as_ref())
                            .map_err(|_| js_error("every random value must be 16 bytes"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                mkey_session::Session::with_random(key, options, Box::new(FixedRandom::new(values)))
            }
            None => mkey_session::Session::new(key, options),
        };

        Ok(Self { inner })
    }

    /// The link is up; begin.
    pub fn started(&mut self) -> Result<JsValue, JsValue> {
        self.poll(Event::Started)
    }

    /// The protocol info read finished. Pass `undefined` when it produced
    /// nothing, for any reason — that is not an error.
    #[wasm_bindgen(js_name = protocolInfo)]
    pub fn protocol_info(&mut self, info: Option<Box<[u8]>>) -> Result<JsValue, JsValue> {
        self.poll(Event::ProtocolInfo(info.as_deref()))
    }

    /// A notification arrived from the lock.
    pub fn notification(&mut self, packet: &[u8]) -> Result<JsValue, JsValue> {
        self.poll(Event::Notification(packet))
    }

    /// The pending timer expired.
    pub fn timer(&mut self, id: &str) -> Result<JsValue, JsValue> {
        let id = parse_timer_id(id).map_err(|e| js_error(&e.to_string()))?;

        self.poll(Event::Timer(id))
    }

    /// The lock dropped the link.
    #[wasm_bindgen(js_name = linkClosed)]
    pub fn link_closed(&mut self) -> Result<JsValue, JsValue> {
        self.poll(Event::LinkClosed)
    }

    /// The caller asked to stop.
    pub fn aborted(&mut self) -> Result<JsValue, JsValue> {
        self.poll(Event::Aborted)
    }

    /// Whether a `done` action has already been produced.
    #[wasm_bindgen(getter)]
    pub fn finished(&self) -> bool {
        self.inner.is_finished()
    }

    fn poll(&mut self, event: Event<'_>) -> Result<JsValue, JsValue> {
        let actions: Vec<WireAction> = self.inner.poll(event).into_iter().map(Into::into).collect();

        // `null`, not `undefined`: "the lock reported no result" is a value
        // the caller compares against, and `undefined` would make every such
        // field indistinguishable from a typo in the field name.
        let serializer = Serializer::new().serialize_missing_as_null(true);

        Ok(actions.serialize(&serializer)?)
    }
}

fn js_error(message: &str) -> JsValue {
    JsValue::from_str(message)
}
