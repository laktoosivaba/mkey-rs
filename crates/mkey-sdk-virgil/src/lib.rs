//! Virgil crypto support for SaltoKS mobile keys.
//!
//! All EC operations run inside the vendor's own build of
//! [virgil-crypto-c](https://github.com/VirgilSecurity/virgil-crypto-c),
//! embedded as `lib/libfoundation.wasm`. The module is an emscripten build
//! with minified export names; `lib/wasm-map.txt` maps the real
//! `vscf_*` / `vsc_*` symbols to the mangled ones used below.
//!
//! Using the WASM rather than a native EC stack is not a convenience: the
//! Virgil key provider only accepts private keys in the exact SEC1
//! `ECPrivateKey` DER shape it emits itself. An OpenSSL PKCS#8 EC key is
//! rejected with `ERROR_BAD_SEC1_PRIVATE_KEY` (-222), so keystore
//! generation has to go through [`generate_virgil_key_pair`].

/// Everything provisioning can fail at.
///
/// Kept apart from [`mkey_core::Error`] on purpose: none of these failures has
/// a `SaltoErrorCode`, because none of them can happen at a door. They belong
/// to the desk where a key is issued, not to the session that spends it.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The decrypted bytes were not a mobile key.
    #[error(transparent)]
    Key(#[from] mkey_core::Error),

    #[error("Virgil container error: {0}")]
    Container(String),

    #[error("RSA decryption error: {0}")]
    RsaDecryption(String),

    #[error("WASM runtime error: {0}")]
    Wasm(String),
}

use base64::Engine as B64Engine;
use once_cell::sync::Lazy;
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use wasmtime::*;

use mkey_core::MobileKey;

/// Embedded Virgil crypto WASM library.
const VIRGIL_WASM: &[u8] = include_bytes!("../lib/libfoundation.wasm");

/// `vscf_alg_id_SECP256R1` — the curve SaltoKS mobile keys use.
const ALG_ID_SECP256R1: i32 = 10;

/// Size of the RSA wrapping key protecting the Virgil private key.
pub const RSA_KEY_BITS: usize = 2048;

/// Capacity handed to `vsc_buffer` when the library exposes no length query.
/// A SECP256R1 SPKI is 91 bytes; 512 leaves ample headroom.
const EXPORT_BUFFER_CAPACITY: i32 = 512;

/// Name of a `vscf_status_t` code, for error messages.
///
/// Only the codes reachable from this crate's call sites are spelled out;
/// see `vscf_status.h` in virgil-crypto-c for the full enumeration.
fn status_name(status: i32) -> &'static str {
    match status {
        0 => "SUCCESS",
        -1 => "ERROR_BAD_ARGUMENTS",
        -2 => "ERROR_UNINITIALIZED",
        -3 => "ERROR_UNHANDLED_THIRDPARTY_ERROR",
        -101 => "ERROR_SMALL_BUFFER",
        -200 => "ERROR_UNSUPPORTED_ALGORITHM",
        -201 => "ERROR_AUTH_FAILED",
        -202 => "ERROR_OUT_OF_DATA",
        -203 => "ERROR_BAD_ASN1",
        -207 => "ERROR_BAD_PKCS8_PUBLIC_KEY",
        -208 => "ERROR_BAD_PKCS8_PRIVATE_KEY",
        -209 => "ERROR_BAD_ENCRYPTED_DATA",
        -210 => "ERROR_RANDOM_FAILED",
        -211 => "ERROR_KEY_GENERATION_FAILED",
        -212 => "ERROR_ENTROPY_SOURCE_FAILED",
        -221 => "ERROR_BAD_SEC1_PUBLIC_KEY",
        -222 => "ERROR_BAD_SEC1_PRIVATE_KEY",
        -223 => "ERROR_BAD_DER_PUBLIC_KEY",
        -224 => "ERROR_BAD_DER_PRIVATE_KEY",
        -225 => "ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM",
        -226 => "ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM",
        -236 => "ERROR_BAD_ASN1_ALGORITHM",
        -237 => "ERROR_BAD_ASN1_ALGORITHM_ECC",
        -301 => "ERROR_NO_MESSAGE_INFO",
        -302 => "ERROR_BAD_MESSAGE_INFO",
        -303 => "ERROR_KEY_RECIPIENT_IS_NOT_FOUND",
        -304 => "ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG",
        -311 => "ERROR_KEY_RECIPIENT_KEK_IS_WRONG",
        -501 => "ERROR_INVALID_PADDING",
        _ => "unknown status",
    }
}

/// Build an `Error` for a non-zero `vscf_status_t`.
fn status_error(op: &str, status: i32) -> Error {
    Error::Wasm(format!(
        "{} failed: Virgil status {} ({})",
        op,
        status,
        status_name(status)
    ))
}

/// The compiled WASM module, shared process-wide.
///
/// Compiling ~1 MB of WASM costs far more than any of the crypto operations
/// performed on it, and both `Engine` and `Module` are immutable and `Sync`.
/// Only the `Store`/`Instance` (and hence all linear memory) are per-call, so
/// runtimes stay isolated from each other.
static COMPILED: Lazy<Result<(Engine, Module), String>> = Lazy::new(|| {
    let engine = Engine::default();
    let module = Module::new(&engine, VIRGIL_WASM)
        .map_err(|e| format!("Failed to load Virgil WASM module: {}", e))?;
    Ok((engine, module))
});

/// Call a WASM function stored in [`Funcs`], mapping traps to [`Error`].
macro_rules! wasm_call {
    ($rt:expr, $func:ident, $args:expr) => {{
        // Borrowing the function and the store touches disjoint fields, so
        // this stays inside what the borrow checker accepts.
        let f = &$rt.funcs.$func;
        f.call(&mut $rt.store, $args)
            .map_err(|e| Error::Wasm(format!("{} trapped: {}", stringify!($func), e)))
    }};
}

/// Typed handles to every WASM export this module uses.
///
/// The field name is the `vscf_*`/`vsc_*` symbol with its prefix dropped; the
/// string literal is the minified export from `lib/wasm-map.txt`.
struct Funcs {
    malloc: TypedFunc<i32, i32>,
    #[allow(dead_code)]
    free: TypedFunc<i32, ()>,

    buffer_new_with_capacity: TypedFunc<i32, i32>,
    buffer_delete: TypedFunc<i32, ()>,
    buffer_bytes: TypedFunc<i32, i32>,
    buffer_len: TypedFunc<i32, i32>,

    data_ctx_size: TypedFunc<(), i32>,
    data_init: TypedFunc<(i32, i32, i32), ()>,

    error_ctx_size: TypedFunc<(), i32>,
    error_reset: TypedFunc<i32, ()>,
    error_status: TypedFunc<i32, i32>,

    ctr_drbg_new: TypedFunc<(), i32>,
    ctr_drbg_delete: TypedFunc<i32, ()>,
    ctr_drbg_setup_defaults: TypedFunc<i32, i32>,

    key_provider_new: TypedFunc<(), i32>,
    key_provider_delete: TypedFunc<i32, ()>,
    key_provider_setup_defaults: TypedFunc<i32, i32>,
    key_provider_use_random: TypedFunc<(i32, i32), ()>,
    key_provider_generate_private_key: TypedFunc<(i32, i32, i32), i32>,
    key_provider_import_private_key: TypedFunc<(i32, i32, i32), i32>,
    key_provider_import_public_key: TypedFunc<(i32, i32, i32), i32>,
    key_provider_export_public_key: TypedFunc<(i32, i32, i32), i32>,
    key_provider_exported_private_key_len: TypedFunc<(i32, i32), i32>,
    key_provider_export_private_key: TypedFunc<(i32, i32, i32), i32>,

    ecc_private_key_extract_public_key: TypedFunc<i32, i32>,

    recipient_cipher_new: TypedFunc<(), i32>,
    recipient_cipher_delete: TypedFunc<i32, ()>,
    recipient_cipher_use_random: TypedFunc<(i32, i32), ()>,
    recipient_cipher_start_decryption_with_key: TypedFunc<(i32, i32, i32, i32), i32>,
    recipient_cipher_decryption_out_len: TypedFunc<(i32, i32), i32>,
    recipient_cipher_process_decryption: TypedFunc<(i32, i32, i32), i32>,
    recipient_cipher_finish_decryption: TypedFunc<(i32, i32), i32>,
}

impl Funcs {
    fn load(instance: &Instance, store: &mut Store<()>) -> Result<Self, Error> {
        Ok(Self {
            malloc: get_func(instance, store, "Es")?,
            free: get_func(instance, store, "Fs")?,

            buffer_new_with_capacity: get_func(instance, store, "ts")?,
            buffer_delete: get_func(instance, store, "us")?,
            buffer_bytes: get_func(instance, store, "xs")?,
            buffer_len: get_func(instance, store, "ys")?,

            data_ctx_size: get_func(instance, store, "zs")?,
            data_init: get_func(instance, store, "As")?,

            error_ctx_size: get_func(instance, store, "Jn")?,
            error_reset: get_func(instance, store, "Kn")?,
            error_status: get_func(instance, store, "Ln")?,

            ctr_drbg_new: get_func(instance, store, "jd")?,
            ctr_drbg_delete: get_func(instance, store, "kd")?,
            ctr_drbg_setup_defaults: get_func(instance, store, "cd")?,

            key_provider_new: get_func(instance, store, "Wo")?,
            key_provider_delete: get_func(instance, store, "Xo")?,
            key_provider_setup_defaults: get_func(instance, store, "_o")?,
            key_provider_use_random: get_func(instance, store, "Zo")?,
            key_provider_generate_private_key: get_func(instance, store, "ap")?,
            key_provider_import_private_key: get_func(instance, store, "fp")?,
            key_provider_import_public_key: get_func(instance, store, "gp")?,
            key_provider_export_public_key: get_func(instance, store, "ip")?,
            key_provider_exported_private_key_len: get_func(instance, store, "jp")?,
            key_provider_export_private_key: get_func(instance, store, "kp")?,

            ecc_private_key_extract_public_key: get_func(instance, store, "Pe")?,

            recipient_cipher_new: get_func(instance, store, "er")?,
            recipient_cipher_delete: get_func(instance, store, "fr")?,
            recipient_cipher_use_random: get_func(instance, store, "hr")?,
            recipient_cipher_start_decryption_with_key: get_func(instance, store, "Ar")?,
            recipient_cipher_decryption_out_len: get_func(instance, store, "Cr")?,
            recipient_cipher_process_decryption: get_func(instance, store, "Dr")?,
            recipient_cipher_finish_decryption: get_func(instance, store, "Er")?,
        })
    }
}

/// Helper to get a typed WASM function.
fn get_func<P: WasmParams, R: WasmResults>(
    instance: &Instance,
    store: &mut Store<()>,
    name: &str,
) -> Result<TypedFunc<P, R>, Error> {
    instance
        .get_typed_func::<P, R>(store, name)
        .map_err(|e| Error::Wasm(format!("Failed to get WASM function '{}': {}", name, e)))
}

/// An instantiated Virgil foundation library with a seeded RNG and a
/// configured key provider.
///
/// Every allocation made through this runtime lives in the instance's linear
/// memory and disappears with the `Store`, so the individual `_delete`
/// calls are hygiene rather than necessity.
struct VirgilRuntime {
    store: Store<()>,
    memory: Memory,
    funcs: Funcs,
    /// `vscf_ctr_drbg_t *`
    rng: i32,
    /// `vscf_key_provider_t *`
    key_provider: i32,
    /// Scratch `vscf_error_t *`, reset before each fallible import.
    error_ctx: i32,
    /// `sizeof(vsc_data_t)`
    data_ctx_size: i32,
}

impl VirgilRuntime {
    /// Instantiate the WASM module and set up RNG + key provider.
    fn new() -> Result<Self, Error> {
        let (engine, module) = COMPILED.as_ref().map_err(|e| Error::Wasm(e.clone()))?;

        let mut linker = Linker::new(engine);
        setup_linker(&mut linker)?;

        let mut store = Store::new(engine, ());
        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| Error::Wasm(format!("Failed to instantiate WASM: {}", e)))?;
        let memory = instance
            .get_memory(&mut store, "o")
            .ok_or_else(|| Error::Wasm("Failed to get WASM memory".into()))?;
        let funcs = Funcs::load(&instance, &mut store)?;

        let mut rt = Self {
            store,
            memory,
            funcs,
            rng: 0,
            key_provider: 0,
            error_ctx: 0,
            data_ctx_size: 0,
        };

        rt.data_ctx_size = wasm_call!(rt, data_ctx_size, ())?;
        let error_ctx_size = wasm_call!(rt, error_ctx_size, ())?;
        rt.error_ctx = rt.alloc(error_ctx_size)?;

        rt.rng = wasm_call!(rt, ctr_drbg_new, ())?;
        let status = wasm_call!(rt, ctr_drbg_setup_defaults, rt.rng)?;
        if status != 0 {
            return Err(status_error("CTR-DRBG setup", status));
        }

        rt.key_provider = wasm_call!(rt, key_provider_new, ())?;
        wasm_call!(rt, key_provider_use_random, (rt.key_provider, rt.rng))?;
        let status = wasm_call!(rt, key_provider_setup_defaults, rt.key_provider)?;
        if status != 0 {
            return Err(status_error("Key provider setup", status));
        }

        Ok(rt)
    }

    /// `malloc` inside the WASM heap.
    fn alloc(&mut self, size: i32) -> Result<i32, Error> {
        let ptr = wasm_call!(self, malloc, size)?;
        if ptr == 0 {
            return Err(Error::Wasm(format!("WASM malloc({}) returned null", size)));
        }
        Ok(ptr)
    }

    /// Copy `data` into a fresh WASM heap allocation.
    fn write_bytes(&mut self, data: &[u8]) -> Result<i32, Error> {
        let ptr = self.alloc(data.len() as i32)?;
        self.memory
            .write(&mut self.store, ptr as usize, data)
            .map_err(|e| Error::Wasm(format!("memory write failed: {}", e)))?;
        Ok(ptr)
    }

    /// Read `len` bytes back out of the WASM heap.
    fn read_bytes(&self, ptr: i32, len: i32) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; len.max(0) as usize];
        self.memory
            .read(&self.store, ptr as usize, &mut buf)
            .map_err(|e| Error::Wasm(format!("memory read failed: {}", e)))?;
        Ok(buf)
    }

    /// Build a `vsc_data_t` view over a copy of `data`.
    fn data(&mut self, data: &[u8]) -> Result<i32, Error> {
        let ptr = self.write_bytes(data)?;
        let ctx = self.alloc(self.data_ctx_size)?;
        wasm_call!(self, data_init, (ctx, ptr, data.len() as i32))?;
        Ok(ctx)
    }

    /// Allocate a `vsc_buffer_t` with the given capacity.
    fn new_buffer(&mut self, capacity: i32) -> Result<i32, Error> {
        let buffer = wasm_call!(self, buffer_new_with_capacity, capacity)?;
        if buffer == 0 {
            return Err(Error::Wasm("vsc_buffer_new returned null".into()));
        }
        Ok(buffer)
    }

    /// Copy a `vsc_buffer_t`'s contents out and release it.
    fn take_buffer(&mut self, buffer: i32) -> Result<Vec<u8>, Error> {
        let ptr = wasm_call!(self, buffer_bytes, buffer)?;
        let len = wasm_call!(self, buffer_len, buffer)?;
        let out = self.read_bytes(ptr, len)?;
        let _ = wasm_call!(self, buffer_delete, buffer);
        Ok(out)
    }

    /// Clear the shared error context before a fallible call.
    fn reset_error(&mut self) -> Result<(), Error> {
        wasm_call!(self, error_reset, self.error_ctx)
    }

    /// Read the status left in the shared error context.
    fn error_status(&mut self) -> Result<i32, Error> {
        wasm_call!(self, error_status, self.error_ctx)
    }

    /// Generate a Virgil-native private key (`vscf_key_provider_generate_private_key`).
    fn generate_private_key(&mut self, alg_id: i32) -> Result<i32, Error> {
        self.reset_error()?;
        let key = wasm_call!(
            self,
            key_provider_generate_private_key,
            (self.key_provider, alg_id, self.error_ctx)
        )?;
        let status = self.error_status()?;
        if key == 0 || status != 0 {
            return Err(status_error(
                &format!("generate_private_key(alg_id={})", alg_id),
                status,
            ));
        }
        Ok(key)
    }

    /// Import a SEC1 `ECPrivateKey` DER as produced by Virgil itself.
    fn import_private_key(&mut self, der: &[u8]) -> Result<i32, Error> {
        let data = self.data(der)?;
        self.reset_error()?;
        let key = wasm_call!(
            self,
            key_provider_import_private_key,
            (self.key_provider, data, self.error_ctx)
        )?;
        let status = self.error_status()?;
        if key == 0 || status != 0 {
            return Err(status_error("import_private_key", status));
        }
        Ok(key)
    }

    /// Import an SPKI public key DER.
    fn import_public_key(&mut self, der: &[u8]) -> Result<i32, Error> {
        let data = self.data(der)?;
        self.reset_error()?;
        let key = wasm_call!(
            self,
            key_provider_import_public_key,
            (self.key_provider, data, self.error_ctx)
        )?;
        let status = self.error_status()?;
        if key == 0 || status != 0 {
            return Err(status_error("import_public_key", status));
        }
        Ok(key)
    }

    /// Export a private key impl as SEC1 `ECPrivateKey` DER.
    fn export_private_key(&mut self, key: i32) -> Result<Vec<u8>, Error> {
        let len = wasm_call!(
            self,
            key_provider_exported_private_key_len,
            (self.key_provider, key)
        )?;
        let buffer = self.new_buffer(len.max(EXPORT_BUFFER_CAPACITY))?;
        let status = wasm_call!(
            self,
            key_provider_export_private_key,
            (self.key_provider, key, buffer)
        )?;
        if status != 0 {
            let _ = wasm_call!(self, buffer_delete, buffer);
            return Err(status_error("export_private_key", status));
        }
        self.take_buffer(buffer)
    }

    /// Export a public key impl as SPKI DER.
    ///
    /// The library exposes no `exported_public_key_len`, hence the fixed
    /// capacity.
    fn export_public_key(&mut self, key: i32) -> Result<Vec<u8>, Error> {
        let buffer = self.new_buffer(EXPORT_BUFFER_CAPACITY)?;
        let status = wasm_call!(
            self,
            key_provider_export_public_key,
            (self.key_provider, key, buffer)
        )?;
        if status != 0 {
            let _ = wasm_call!(self, buffer_delete, buffer);
            return Err(status_error("export_public_key", status));
        }
        self.take_buffer(buffer)
    }

    /// Derive the public key impl belonging to an EC private key impl.
    fn extract_public_key(&mut self, private_key: i32) -> Result<i32, Error> {
        let key = wasm_call!(self, ecc_private_key_extract_public_key, private_key)?;
        if key == 0 {
            return Err(Error::Wasm(
                "ecc_private_key_extract_public_key returned null".into(),
            ));
        }
        Ok(key)
    }
}

impl Drop for VirgilRuntime {
    fn drop(&mut self) {
        // The whole linear memory goes away with the store; this only keeps
        // the library's own refcounting happy for long-lived runtimes.
        if self.key_provider != 0 {
            let _ = wasm_call!(self, key_provider_delete, self.key_provider);
        }
        if self.rng != 0 {
            let _ = wasm_call!(self, ctr_drbg_delete, self.rng);
        }
    }
}

/// Set up the WASM linker with emscripten runtime stubs.
fn setup_linker(linker: &mut Linker<()>) -> Result<(), Error> {
    linker
        .func_wrap("a", "a", |_a: i32, _b: i32, _c: i32| -> i32 { 0 })
        .map_err(|e| Error::Wasm(e.to_string()))?;
    linker
        .func_wrap("a", "b", |_a: i32| -> i32 { 0 })
        .map_err(|e| Error::Wasm(e.to_string()))?;
    // fd_write - must write to nwritten or it loops forever
    linker
        .func_wrap(
            "a",
            "c",
            |mut caller: Caller<'_, ()>, _: i32, iovs: i32, iovs_len: i32, nwritten: i32| -> i32 {
                let memory = caller.get_export("o").unwrap().into_memory().unwrap();
                let mut total: u32 = 0;
                for i in 0..iovs_len {
                    let iov_base = (iovs + i * 8) as usize;
                    let mut len_bytes = [0u8; 4];
                    memory.read(&caller, iov_base + 4, &mut len_bytes).ok();
                    total += u32::from_le_bytes(len_bytes);
                }
                memory
                    .write(&mut caller, nwritten as usize, &total.to_le_bytes())
                    .ok();
                0
            },
        )
        .map_err(|e| Error::Wasm(e.to_string()))?;
    linker
        .func_wrap("a", "d", |_a: i32, _b: i32, _c: i32, _d: i32| -> i32 { 0 })
        .map_err(|e| Error::Wasm(e.to_string()))?;
    linker
        .func_wrap("a", "e", |_a: i32, _b: i32| {})
        .map_err(|e| Error::Wasm(e.to_string()))?;
    linker
        .func_wrap("a", "f", |_a: i32| {})
        .map_err(|e| Error::Wasm(e.to_string()))?;
    linker
        .func_wrap("a", "g", || {})
        .map_err(|e| Error::Wasm(e.to_string()))?;
    linker
        .func_wrap("a", "h", |_a: i32, _b: f64| -> i32 { 0 })
        .map_err(|e| Error::Wasm(e.to_string()))?;
    // emscripten_get_now
    linker
        .func_wrap("a", "i", || -> f64 {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as f64
        })
        .map_err(|e| Error::Wasm(e.to_string()))?;
    linker
        .func_wrap("a", "j", |_a: i32| -> i32 { 0 })
        .map_err(|e| Error::Wasm(e.to_string()))?;
    linker
        .func_wrap("a", "k", |_a: i32, _b: i32, _c: i32, _d: i32| -> i32 { 0 })
        .map_err(|e| Error::Wasm(e.to_string()))?;
    linker
        .func_wrap("a", "l", |_a: i32, _b: i64, _c: i32, _d: i32| -> i32 { 0 })
        .map_err(|e| Error::Wasm(e.to_string()))?;
    linker
        .func_wrap("a", "m", |_a: i32, _b: i32, _c: i32| -> i32 { 0 })
        .map_err(|e| Error::Wasm(e.to_string()))?;
    linker
        .func_wrap("a", "n", || {})
        .map_err(|e| Error::Wasm(e.to_string()))?;
    Ok(())
}

/// Parsed Virgil encrypted container.
#[derive(Debug)]
pub struct VirgilContainer<'a> {
    pub message_info: &'a [u8],
    pub encrypted_content: &'a [u8],
    pub recipient_id: Vec<u8>,
}

/// Extract recipient_id from Virgil message_info ASN.1 structure.
/// Looks for pattern: A0 22 04 20 <32 bytes recipient_id>
fn extract_recipient_id(message_info: &[u8]) -> Option<Vec<u8>> {
    for i in 0..message_info.len().saturating_sub(35) {
        if message_info[i] == 0xa0
            && message_info[i + 1] == 0x22
            && message_info[i + 2] == 0x04
            && message_info[i + 3] == 0x20
        {
            return Some(message_info[i + 4..i + 4 + 32].to_vec());
        }
    }
    None
}

/// Parse a Virgil encrypted container into its components.
///
/// The container structure:
/// - Signature header (variable length)
/// - "VIRGIL-DATA-SIGNATURE" marker
/// - ASN.1 SEQUENCE (message_info) followed by encrypted content
pub fn parse_virgil_container(data: &[u8]) -> Result<VirgilContainer<'_>, Error> {
    let marker = b"VIRGIL-DATA-SIGNATURE";
    let marker_pos = data
        .windows(marker.len())
        .position(|w| w == marker)
        .ok_or_else(|| Error::Container("VIRGIL-DATA-SIGNATURE marker not found".into()))?;

    let after_marker = &data[marker_pos + marker.len()..];

    if after_marker.is_empty() || after_marker[0] != 0x30 {
        return Err(Error::Container(
            "Expected SEQUENCE tag (0x30) at start of message_info".into(),
        ));
    }

    let (msg_info_len, header_len) = if after_marker[1] < 0x80 {
        (after_marker[1] as usize, 2usize)
    } else if after_marker[1] == 0x81 {
        (after_marker[2] as usize, 3usize)
    } else if after_marker[1] == 0x82 {
        let len = ((after_marker[2] as usize) << 8) | (after_marker[3] as usize);
        (len, 4usize)
    } else {
        return Err(Error::Container(format!(
            "Unsupported ASN.1 length encoding: 0x{:02x}",
            after_marker[1]
        )));
    };

    let msg_info_total_len = header_len + msg_info_len;
    let message_info = &after_marker[..msg_info_total_len];
    let encrypted_content = &after_marker[msg_info_total_len..];

    let recipient_id = extract_recipient_id(message_info).ok_or_else(|| {
        Error::Container("Failed to extract recipient_id from message_info".into())
    })?;

    Ok(VirgilContainer {
        message_info,
        encrypted_content,
        recipient_id,
    })
}

/// A Virgil SECP256R1 key pair, in the DER encodings SaltoKS expects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirgilKeyPair {
    /// SEC1 `ECPrivateKey` DER, exactly as the Virgil key provider emits it.
    /// This is what gets base64-wrapped and RSA-encrypted into `sdk.txt`.
    pub private_key_der: Vec<u8>,
    /// `SubjectPublicKeyInfo` DER — base64 of this is registered with the
    /// SaltoKS API as the device public key.
    pub public_key_der: Vec<u8>,
}

/// Generate a fresh SECP256R1 key pair using Virgil's own key provider.
///
/// The private key must come from Virgil: its key provider rejects PKCS#8 EC
/// keys produced by OpenSSL with `ERROR_BAD_SEC1_PRIVATE_KEY` (-222), so a
/// keystore built with `openssl ecparam` cannot be used to decrypt
/// `mkey_data`.
pub fn generate_virgil_key_pair() -> Result<VirgilKeyPair, Error> {
    let mut rt = VirgilRuntime::new()?;
    let private_key = rt.generate_private_key(ALG_ID_SECP256R1)?;
    let private_key_der = rt.export_private_key(private_key)?;
    let public_key = rt.extract_public_key(private_key)?;
    let public_key_der = rt.export_public_key(public_key)?;
    Ok(VirgilKeyPair {
        private_key_der,
        public_key_der,
    })
}

/// Derive the SPKI public key DER belonging to a Virgil SEC1 private key.
///
/// This runs the same import path `decode` uses, so a successful result also
/// proves the private key is usable for `mkey_data` decryption.
pub fn derive_virgil_public_key(private_key_der: &[u8]) -> Result<Vec<u8>, Error> {
    let mut rt = VirgilRuntime::new()?;
    let private_key = rt.import_private_key(private_key_der)?;
    let public_key = rt.extract_public_key(private_key)?;
    rt.export_public_key(public_key)
}

/// Re-encode an SPKI public key DER through Virgil (import then export).
///
/// Used by `keystore_check` to prove the stored public key is one Virgil —
/// and therefore the SaltoKS backend — accepts.
pub fn roundtrip_virgil_public_key(public_key_der: &[u8]) -> Result<Vec<u8>, Error> {
    let mut rt = VirgilRuntime::new()?;
    let public_key = rt.import_public_key(public_key_der)?;
    rt.export_public_key(public_key)
}

/// Generate the RSA wrapping key for a keystore, as PKCS#8 DER.
///
/// This is the key stored as `keystore/private_key.der`; it protects the
/// Virgil private key at rest and is never seen by SaltoKS.
pub fn generate_rsa_private_key() -> Result<Vec<u8>, Error> {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)
        .map_err(|e| Error::RsaDecryption(format!("RSA key generation failed: {}", e)))?;
    let der = key
        .to_pkcs8_der()
        .map_err(|e| Error::RsaDecryption(format!("PKCS8 encoding failed: {}", e)))?;
    Ok(der.as_bytes().to_vec())
}

/// Parse an RSA public key from SPKI DER, PKCS#1 DER, or a PKCS#8 private key.
fn rsa_public_key(rsa_key_der: &[u8]) -> Result<RsaPublicKey, Error> {
    if let Ok(key) = RsaPublicKey::from_public_key_der(rsa_key_der) {
        return Ok(key);
    }
    if let Ok(key) = <RsaPublicKey as rsa::pkcs1::DecodeRsaPublicKey>::from_pkcs1_der(rsa_key_der) {
        return Ok(key);
    }
    RsaPrivateKey::from_pkcs8_der(rsa_key_der)
        .map(|k| k.to_public_key())
        .map_err(|e| {
            Error::RsaDecryption(format!(
                "Not an RSA public key (SPKI/PKCS1) nor a PKCS8 private key: {}",
                e
            ))
        })
}

/// Encrypt a Virgil EC private key for storage in `keystore/sdk.txt`.
///
/// The inverse of [`decrypt_virgil_private_key`]: the DER is base64-encoded,
/// and that ASCII string is what gets RSA PKCS#1 v1.5 encrypted. The returned
/// bytes are the raw ciphertext (`sdk.txt` holds its base64).
///
/// `rsa_key_der` may be an RSA public key (SPKI or PKCS#1 DER) or the PKCS#8
/// private key, whose public half is then used.
pub fn encrypt_virgil_private_key(
    rsa_key_der: &[u8],
    private_key_der: &[u8],
) -> Result<Vec<u8>, Error> {
    let public_key = rsa_public_key(rsa_key_der)?;
    let wrapped = base64::engine::general_purpose::STANDARD.encode(private_key_der);
    let mut rng = rand::thread_rng();
    public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, wrapped.as_bytes())
        .map_err(|e| Error::RsaDecryption(format!("RSA encryption failed: {}", e)))
}

/// Decrypt the Virgil EC private key using RSA PKCS1v15.
///
/// The encrypted key is `RSA_Encrypt(Base64(VirgilPrivateKey))`.
/// Returns the raw DER bytes of the Virgil private key.
pub fn decrypt_virgil_private_key(
    rsa_key_der: &[u8],
    encrypted_key: &[u8],
) -> Result<Vec<u8>, Error> {
    let rsa_private_key = RsaPrivateKey::from_pkcs8_der(rsa_key_der)
        .map_err(|e| Error::RsaDecryption(format!("Failed to parse RSA key: {}", e)))?;

    let decrypted_b64 = rsa_private_key
        .decrypt(Pkcs1v15Encrypt, encrypted_key)
        .map_err(|e| Error::RsaDecryption(format!("RSA decryption failed: {}", e)))?;

    let decrypted_str = String::from_utf8(decrypted_b64)
        .map_err(|e| Error::RsaDecryption(format!("Decrypted key not valid UTF-8: {}", e)))?;

    base64::engine::general_purpose::STANDARD
        .decode(decrypted_str.trim())
        .map_err(|e| Error::RsaDecryption(format!("Base64 decode failed: {}", e)))
}

/// Decrypt a Virgil-encrypted mobile key using the embedded WASM Virgil crypto library.
///
/// # Arguments
/// * `rsa_private_key_der` — RSA private key in PKCS8 DER format
/// * `encrypted_virgil_key` — RSA-encrypted (base64-wrapped) Virgil EC private key
/// * `encrypted_mkey_data` — raw bytes of the Virgil encrypted container
///
/// # Returns
/// A parsed `MobileKey` on success.
pub fn decrypt_mobile_key(
    rsa_private_key_der: &[u8],
    encrypted_virgil_key: &[u8],
    encrypted_mkey_data: &[u8],
) -> Result<MobileKey, Error> {
    // Step 1: Parse the Virgil container
    let container = parse_virgil_container(encrypted_mkey_data)?;

    // Step 2: Decrypt the Virgil EC private key with RSA
    let private_key_der = decrypt_virgil_private_key(rsa_private_key_der, encrypted_virgil_key)?;

    // Step 3: Set up the WASM runtime and import the Virgil private key
    let mut rt = VirgilRuntime::new()?;
    let private_key = rt.import_private_key(&private_key_der)?;

    // Step 4: Set up the recipient cipher
    let recipient_cipher = wasm_call!(rt, recipient_cipher_new, ())?;
    wasm_call!(rt, recipient_cipher_use_random, (recipient_cipher, rt.rng))?;

    let recipient_id = rt.data(&container.recipient_id)?;
    let message_info = rt.data(container.message_info)?;

    let status = wasm_call!(
        rt,
        recipient_cipher_start_decryption_with_key,
        (recipient_cipher, recipient_id, private_key, message_info)
    )?;
    if status != 0 {
        let _ = wasm_call!(rt, recipient_cipher_delete, recipient_cipher);
        return Err(status_error("start_decryption_with_key", status));
    }

    // Step 5: Process the encrypted content
    let content = rt.data(container.encrypted_content)?;
    let process_out_len = wasm_call!(
        rt,
        recipient_cipher_decryption_out_len,
        (recipient_cipher, container.encrypted_content.len() as i32)
    )?;
    let process_buffer = rt.new_buffer(process_out_len.clamp(64, 10000))?;
    let status = wasm_call!(
        rt,
        recipient_cipher_process_decryption,
        (recipient_cipher, content, process_buffer)
    )?;
    if status != 0 {
        let _ = wasm_call!(rt, buffer_delete, process_buffer);
        let _ = wasm_call!(rt, recipient_cipher_delete, recipient_cipher);
        return Err(status_error("process_decryption", status));
    }

    // Step 6: Finish decryption
    let finish_out_len = wasm_call!(
        rt,
        recipient_cipher_decryption_out_len,
        (recipient_cipher, 0)
    )?;
    let finish_buffer = rt.new_buffer(finish_out_len.clamp(64, 10000))?;
    let status = wasm_call!(
        rt,
        recipient_cipher_finish_decryption,
        (recipient_cipher, finish_buffer)
    )?;
    if status != 0 {
        let _ = wasm_call!(rt, buffer_delete, finish_buffer);
        let _ = wasm_call!(rt, buffer_delete, process_buffer);
        let _ = wasm_call!(rt, recipient_cipher_delete, recipient_cipher);
        return Err(status_error("finish_decryption", status));
    }

    let mut decrypted = rt.take_buffer(process_buffer)?;
    decrypted.extend(rt.take_buffer(finish_buffer)?);
    let _ = wasm_call!(rt, recipient_cipher_delete, recipient_cipher);

    if decrypted.is_empty() {
        return Err(Error::Wasm("Decryption produced no output".into()));
    }

    Ok(MobileKey::from_bytes(&decrypted)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs8::EncodePublicKey;
    use std::sync::OnceLock;

    /// A throwaway SECP256R1 key in the encoding OpenSSL produces:
    ///
    /// ```text
    /// openssl ecparam -name prime256v1 -genkey -noout \
    ///   | openssl pkcs8 -topk8 -nocrypt -outform DER
    /// ```
    ///
    /// It exists only to pin the fact that Virgil refuses PKCS#8 EC keys.
    const OPENSSL_PKCS8_EC_KEY_HEX: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104\
2004e4efe2b7417fba52e529df32bc960f210fb1836455f3c66b578dc79d8f4d25a1440342000445797eeed7a9971a188a773810a0cb97d3\
8b3b0293c3743c2cfb468e020ca00b62a2f5a256fd8c9d08dcaa65280c58ac06dd69a33d1a945fc08c380502db27f1";

    /// RSA-2048 generation is slow enough to be worth doing once per process.
    fn test_rsa_key() -> &'static [u8] {
        static KEY: OnceLock<Vec<u8>> = OnceLock::new();
        KEY.get_or_init(|| generate_rsa_private_key().expect("RSA-2048 generation"))
    }

    #[test]
    fn generated_key_pair_is_self_consistent() {
        let pair = generate_virgil_key_pair().expect("key generation");

        // SEC1 ECPrivateKey and SPKI are both DER SEQUENCEs.
        assert_eq!(pair.private_key_der[0], 0x30);
        assert_eq!(pair.public_key_der[0], 0x30);
        assert!(
            (100..=140).contains(&pair.private_key_der.len()),
            "unexpected SEC1 length {}",
            pair.private_key_der.len()
        );
        assert_eq!(pair.public_key_der.len(), 91, "SECP256R1 SPKI is 91 bytes");

        let derived = derive_virgil_public_key(&pair.private_key_der).expect("derive public key");
        assert_eq!(derived, pair.public_key_der);

        let roundtripped =
            roundtrip_virgil_public_key(&pair.public_key_der).expect("public key round trip");
        assert_eq!(roundtripped, pair.public_key_der);
    }

    #[test]
    fn generated_private_key_imports_and_exports_unchanged() {
        let pair = generate_virgil_key_pair().expect("key generation");

        let mut rt = VirgilRuntime::new().expect("runtime");
        let key = rt
            .import_private_key(&pair.private_key_der)
            .expect("import of a Virgil-generated SEC1 key must succeed");
        let exported = rt.export_private_key(key).expect("export");
        assert_eq!(exported, pair.private_key_der);
    }

    #[test]
    fn virgil_private_key_survives_the_rsa_wrapping() {
        let rsa_der = test_rsa_key();
        let pair = generate_virgil_key_pair().expect("key generation");

        // Wrap with the PKCS#8 private key (what `keystore_gen` has at hand).
        let sdk_blob = encrypt_virgil_private_key(rsa_der, &pair.private_key_der).expect("encrypt");
        assert_eq!(sdk_blob.len(), RSA_KEY_BITS / 8);
        let recovered = decrypt_virgil_private_key(rsa_der, &sdk_blob).expect("decrypt");
        assert_eq!(recovered, pair.private_key_der);

        // Wrapping with just the SPKI public key must give the same result.
        let spki = RsaPrivateKey::from_pkcs8_der(rsa_der)
            .unwrap()
            .to_public_key()
            .to_public_key_der()
            .unwrap();
        let sdk_blob = encrypt_virgil_private_key(spki.as_bytes(), &pair.private_key_der)
            .expect("encrypt with SPKI");
        let recovered = decrypt_virgil_private_key(rsa_der, &sdk_blob).expect("decrypt");
        assert_eq!(recovered, pair.private_key_der);
    }

    /// Minimal stand-in for a SaltoKS container: arbitrary signature header,
    /// the marker, a message_info SEQUENCE carrying the 32-byte recipient id,
    /// then the ciphertext.
    fn fake_container(recipient_id: &[u8; 32], ciphertext: &[u8]) -> Vec<u8> {
        let mut message_info = vec![0xa0, 0x22, 0x04, 0x20];
        message_info.extend_from_slice(recipient_id);
        let mut out = b"\x30\x0ajunk-headerVIRGIL-DATA-SIGNATURE".to_vec();
        out.push(0x30);
        out.push(message_info.len() as u8);
        out.extend_from_slice(&message_info);
        out.extend_from_slice(ciphertext);
        out
    }

    #[test]
    fn container_is_split_at_the_signature_marker() {
        let container = fake_container(&[0xab; 32], &[0x42; 48]);
        let parsed = parse_virgil_container(&container).expect("parse");
        assert_eq!(parsed.recipient_id, vec![0xab; 32]);
        assert_eq!(parsed.message_info[0], 0x30);
        assert_eq!(parsed.message_info.len(), 2 + 4 + 32);
        assert_eq!(parsed.encrypted_content, &[0x42; 48]);
    }

    #[test]
    fn container_without_the_marker_is_rejected() {
        let err = parse_virgil_container(&[0x30, 0x02, 0x00, 0x00]).unwrap_err();
        assert!(matches!(err, Error::Container(_)), "got {}", err);
    }

    #[test]
    fn openssl_pkcs8_ec_key_is_rejected() {
        let der = hex::decode(OPENSSL_PKCS8_EC_KEY_HEX).expect("test vector");
        let err = derive_virgil_public_key(&der)
            .expect_err("Virgil must reject an OpenSSL PKCS#8 EC key");
        let msg = err.to_string();
        assert!(
            msg.contains("-222") && msg.contains("ERROR_BAD_SEC1_PRIVATE_KEY"),
            "error should name the Virgil status, got: {}",
            msg
        );
    }
}
