use base64::Engine as B64Engine;
use pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use wasmtime::*;

use crate::data::mobile_key::MobileKey;
use crate::Error;

/// Embedded Virgil crypto WASM library.
const VIRGIL_WASM: &[u8] = include_bytes!("../../lib/libfoundation.wasm");

/// Helper struct for WASM memory operations.
struct WasmHelper<'a> {
    store: &'a mut Store<()>,
    memory: Memory,
    malloc: TypedFunc<i32, i32>,
    free: TypedFunc<i32, ()>,
}

impl<'a> WasmHelper<'a> {
    fn write_bytes(&mut self, data: &[u8]) -> Result<i32, Error> {
        let ptr = self
            .malloc
            .call(&mut *self.store, data.len() as i32)
            .map_err(|e| Error::WasmError(format!("malloc failed: {}", e)))?;
        self.memory
            .write(&mut *self.store, ptr as usize, data)
            .map_err(|e| Error::WasmError(format!("memory write failed: {}", e)))?;
        Ok(ptr)
    }

    fn read_bytes(&self, ptr: i32, len: i32) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; len as usize];
        self.memory
            .read(&self.store, ptr as usize, &mut buf)
            .map_err(|e| Error::WasmError(format!("memory read failed: {}", e)))?;
        Ok(buf)
    }

    #[allow(dead_code)]
    fn free_ptr(&mut self, ptr: i32) -> Result<(), Error> {
        self.free
            .call(&mut *self.store, ptr)
            .map_err(|e| Error::WasmError(format!("free failed: {}", e)))?;
        Ok(())
    }
}

/// Parsed Virgil encrypted container.
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
        .ok_or_else(|| {
            Error::VirgilContainerError("VIRGIL-DATA-SIGNATURE marker not found".into())
        })?;

    let after_marker = &data[marker_pos + marker.len()..];

    if after_marker.is_empty() || after_marker[0] != 0x30 {
        return Err(Error::VirgilContainerError(
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
        return Err(Error::VirgilContainerError(format!(
            "Unsupported ASN.1 length encoding: 0x{:02x}",
            after_marker[1]
        )));
    };

    let msg_info_total_len = header_len + msg_info_len;
    let message_info = &after_marker[..msg_info_total_len];
    let encrypted_content = &after_marker[msg_info_total_len..];

    let recipient_id = extract_recipient_id(message_info).ok_or_else(|| {
        Error::VirgilContainerError("Failed to extract recipient_id from message_info".into())
    })?;

    Ok(VirgilContainer {
        message_info,
        encrypted_content,
        recipient_id,
    })
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
        .map_err(|e| Error::RsaDecryptionError(format!("Failed to parse RSA key: {}", e)))?;

    let decrypted_b64 = rsa_private_key
        .decrypt(Pkcs1v15Encrypt, encrypted_key)
        .map_err(|e| Error::RsaDecryptionError(format!("RSA decryption failed: {}", e)))?;

    let decrypted_str = String::from_utf8(decrypted_b64)
        .map_err(|e| Error::RsaDecryptionError(format!("Decrypted key not valid UTF-8: {}", e)))?;

    base64::engine::general_purpose::STANDARD
        .decode(decrypted_str.trim())
        .map_err(|e| Error::RsaDecryptionError(format!("Base64 decode failed: {}", e)))
}

/// Set up the WASM linker with emscripten runtime stubs.
fn setup_linker(linker: &mut Linker<()>) -> Result<(), Error> {
    linker
        .func_wrap("a", "a", |_a: i32, _b: i32, _c: i32| -> i32 { 0 })
        .map_err(|e| Error::WasmError(e.to_string()))?;
    linker
        .func_wrap("a", "b", |_a: i32| -> i32 { 0 })
        .map_err(|e| Error::WasmError(e.to_string()))?;
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
        .map_err(|e| Error::WasmError(e.to_string()))?;
    linker
        .func_wrap("a", "d", |_a: i32, _b: i32, _c: i32, _d: i32| -> i32 { 0 })
        .map_err(|e| Error::WasmError(e.to_string()))?;
    linker
        .func_wrap("a", "e", |_a: i32, _b: i32| {})
        .map_err(|e| Error::WasmError(e.to_string()))?;
    linker
        .func_wrap("a", "f", |_a: i32| {})
        .map_err(|e| Error::WasmError(e.to_string()))?;
    linker
        .func_wrap("a", "g", || {})
        .map_err(|e| Error::WasmError(e.to_string()))?;
    linker
        .func_wrap("a", "h", |_a: i32, _b: f64| -> i32 { 0 })
        .map_err(|e| Error::WasmError(e.to_string()))?;
    // emscripten_get_now
    linker
        .func_wrap("a", "i", || -> f64 {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as f64
        })
        .map_err(|e| Error::WasmError(e.to_string()))?;
    linker
        .func_wrap("a", "j", |_a: i32| -> i32 { 0 })
        .map_err(|e| Error::WasmError(e.to_string()))?;
    linker
        .func_wrap("a", "k", |_a: i32, _b: i32, _c: i32, _d: i32| -> i32 { 0 })
        .map_err(|e| Error::WasmError(e.to_string()))?;
    linker
        .func_wrap("a", "l", |_a: i32, _b: i64, _c: i32, _d: i32| -> i32 { 0 })
        .map_err(|e| Error::WasmError(e.to_string()))?;
    linker
        .func_wrap("a", "m", |_a: i32, _b: i32, _c: i32| -> i32 { 0 })
        .map_err(|e| Error::WasmError(e.to_string()))?;
    linker
        .func_wrap("a", "n", || {})
        .map_err(|e| Error::WasmError(e.to_string()))?;
    Ok(())
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

    // Step 3: Set up WASM runtime
    let engine = Engine::default();
    let module = Module::new(&engine, VIRGIL_WASM)
        .map_err(|e| Error::WasmError(format!("Failed to load WASM module: {}", e)))?;

    let mut linker = Linker::new(&engine);
    setup_linker(&mut linker)?;

    let mut store = Store::new(&engine, ());
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| Error::WasmError(format!("Failed to instantiate WASM: {}", e)))?;

    let memory = instance
        .get_memory(&mut store, "o")
        .ok_or_else(|| Error::WasmError("Failed to get WASM memory".into()))?;

    // Get WASM functions
    let malloc = get_func::<i32, i32>(&instance, &mut store, "Es")?;
    let free = get_func::<i32, ()>(&instance, &mut store, "Fs")?;

    let vsc_buffer_new_with_capacity = get_func::<i32, i32>(&instance, &mut store, "ts")?;
    let vsc_buffer_delete = get_func::<i32, ()>(&instance, &mut store, "us")?;
    let vsc_buffer_bytes = get_func::<i32, i32>(&instance, &mut store, "xs")?;
    let vsc_buffer_len = get_func::<i32, i32>(&instance, &mut store, "ys")?;

    let vsc_data_ctx_size = get_func::<(), i32>(&instance, &mut store, "zs")?;
    let vsc_data = get_func::<(i32, i32, i32), ()>(&instance, &mut store, "As")?;

    let vscf_ctr_drbg_new = get_func::<(), i32>(&instance, &mut store, "jd")?;
    let vscf_ctr_drbg_delete = get_func::<i32, ()>(&instance, &mut store, "kd")?;
    let vscf_ctr_drbg_setup_defaults = get_func::<i32, i32>(&instance, &mut store, "cd")?;

    let vscf_key_provider_new = get_func::<(), i32>(&instance, &mut store, "Wo")?;
    let vscf_key_provider_delete = get_func::<i32, ()>(&instance, &mut store, "Xo")?;
    let vscf_key_provider_setup_defaults = get_func::<i32, i32>(&instance, &mut store, "_o")?;
    let vscf_key_provider_use_random = get_func::<(i32, i32), ()>(&instance, &mut store, "Zo")?;
    let vscf_key_provider_import_private_key =
        get_func::<(i32, i32, i32), i32>(&instance, &mut store, "fp")?;

    let vscf_recipient_cipher_new = get_func::<(), i32>(&instance, &mut store, "er")?;
    let vscf_recipient_cipher_delete = get_func::<i32, ()>(&instance, &mut store, "fr")?;
    let vscf_recipient_cipher_use_random = get_func::<(i32, i32), ()>(&instance, &mut store, "hr")?;
    let vscf_recipient_cipher_start_decryption_with_key =
        get_func::<(i32, i32, i32, i32), i32>(&instance, &mut store, "Ar")?;
    let vscf_recipient_cipher_decryption_out_len =
        get_func::<(i32, i32), i32>(&instance, &mut store, "Cr")?;
    let vscf_recipient_cipher_process_decryption =
        get_func::<(i32, i32, i32), i32>(&instance, &mut store, "Dr")?;
    let vscf_recipient_cipher_finish_decryption =
        get_func::<(i32, i32), i32>(&instance, &mut store, "Er")?;

    let mut helper = WasmHelper {
        store: &mut store,
        memory,
        malloc,
        free,
    };

    // Step 4: Initialize Virgil crypto components
    let rng = vscf_ctr_drbg_new
        .call(&mut *helper.store, ())
        .map_err(|e| Error::WasmError(format!("ctr_drbg_new failed: {}", e)))?;
    let status = vscf_ctr_drbg_setup_defaults
        .call(&mut *helper.store, rng)
        .map_err(|e| Error::WasmError(format!("ctr_drbg_setup failed: {}", e)))?;
    if status != 0 {
        return Err(Error::WasmError(format!(
            "CTR-DRBG setup failed: {}",
            status
        )));
    }

    let key_provider = vscf_key_provider_new
        .call(&mut *helper.store, ())
        .map_err(|e| Error::WasmError(format!("key_provider_new failed: {}", e)))?;
    vscf_key_provider_use_random
        .call(&mut *helper.store, (key_provider, rng))
        .map_err(|e| Error::WasmError(format!("key_provider_use_random failed: {}", e)))?;
    let status = vscf_key_provider_setup_defaults
        .call(&mut *helper.store, key_provider)
        .map_err(|e| Error::WasmError(format!("key_provider_setup failed: {}", e)))?;
    if status != 0 {
        return Err(Error::WasmError(format!(
            "Key provider setup failed: {}",
            status
        )));
    }

    // Step 5: Import the Virgil private key
    let data_ctx_size = vsc_data_ctx_size
        .call(&mut *helper.store, ())
        .map_err(|e| Error::WasmError(format!("vsc_data_ctx_size failed: {}", e)))?;

    let key_data_ptr = helper.write_bytes(&private_key_der)?;
    let key_data_ctx = helper
        .malloc
        .call(&mut *helper.store, data_ctx_size)
        .map_err(|e| Error::WasmError(format!("malloc failed: {}", e)))?;
    vsc_data
        .call(
            &mut *helper.store,
            (key_data_ctx, key_data_ptr, private_key_der.len() as i32),
        )
        .map_err(|e| Error::WasmError(format!("vsc_data failed: {}", e)))?;

    let error_ctx = helper
        .malloc
        .call(&mut *helper.store, 8)
        .map_err(|e| Error::WasmError(format!("malloc failed: {}", e)))?;

    let private_key = vscf_key_provider_import_private_key
        .call(&mut *helper.store, (key_provider, key_data_ctx, error_ctx))
        .map_err(|e| Error::WasmError(format!("import_private_key failed: {}", e)))?;

    if private_key == 0 {
        return Err(Error::WasmError("Failed to import private key".into()));
    }

    // Step 6: Set up recipient cipher and decrypt
    let recipient_cipher = vscf_recipient_cipher_new
        .call(&mut *helper.store, ())
        .map_err(|e| Error::WasmError(format!("recipient_cipher_new failed: {}", e)))?;
    vscf_recipient_cipher_use_random
        .call(&mut *helper.store, (recipient_cipher, rng))
        .map_err(|e| Error::WasmError(format!("recipient_cipher_use_random failed: {}", e)))?;

    // Prepare recipient ID
    let recipient_id_ptr = helper.write_bytes(&container.recipient_id)?;
    let recipient_id_ctx = helper
        .malloc
        .call(&mut *helper.store, data_ctx_size)
        .map_err(|e| Error::WasmError(format!("malloc failed: {}", e)))?;
    vsc_data
        .call(
            &mut *helper.store,
            (
                recipient_id_ctx,
                recipient_id_ptr,
                container.recipient_id.len() as i32,
            ),
        )
        .map_err(|e| Error::WasmError(format!("vsc_data failed: {}", e)))?;

    // Prepare message info
    let message_info_ptr = helper.write_bytes(container.message_info)?;
    let message_info_ctx = helper
        .malloc
        .call(&mut *helper.store, data_ctx_size)
        .map_err(|e| Error::WasmError(format!("malloc failed: {}", e)))?;
    vsc_data
        .call(
            &mut *helper.store,
            (
                message_info_ctx,
                message_info_ptr,
                container.message_info.len() as i32,
            ),
        )
        .map_err(|e| Error::WasmError(format!("vsc_data failed: {}", e)))?;

    // Start decryption
    let status = vscf_recipient_cipher_start_decryption_with_key
        .call(
            &mut *helper.store,
            (
                recipient_cipher,
                recipient_id_ctx,
                private_key,
                message_info_ctx,
            ),
        )
        .map_err(|e| Error::WasmError(format!("start_decryption failed: {}", e)))?;

    if status != 0 {
        // Cleanup
        let _ = vscf_recipient_cipher_delete.call(&mut *helper.store, recipient_cipher);
        let _ = vscf_key_provider_delete.call(&mut *helper.store, key_provider);
        let _ = vscf_ctr_drbg_delete.call(&mut *helper.store, rng);
        return Err(Error::WasmError(format!(
            "start_decryption_with_key failed: {} (error -302 = BAD_MESSAGE_INFO)",
            status
        )));
    }

    // Process encrypted content
    let content_ptr = helper.write_bytes(container.encrypted_content)?;
    let content_ctx = helper
        .malloc
        .call(&mut *helper.store, data_ctx_size)
        .map_err(|e| Error::WasmError(format!("malloc failed: {}", e)))?;
    vsc_data
        .call(
            &mut *helper.store,
            (
                content_ctx,
                content_ptr,
                container.encrypted_content.len() as i32,
            ),
        )
        .map_err(|e| Error::WasmError(format!("vsc_data failed: {}", e)))?;

    let process_out_len = vscf_recipient_cipher_decryption_out_len
        .call(
            &mut *helper.store,
            (recipient_cipher, container.encrypted_content.len() as i32),
        )
        .map_err(|e| Error::WasmError(format!("decryption_out_len failed: {}", e)))?;

    let process_buffer_size = (process_out_len.max(64)).min(10000);
    let process_buffer = vsc_buffer_new_with_capacity
        .call(&mut *helper.store, process_buffer_size)
        .map_err(|e| Error::WasmError(format!("buffer_new failed: {}", e)))?;

    let status = vscf_recipient_cipher_process_decryption
        .call(
            &mut *helper.store,
            (recipient_cipher, content_ctx, process_buffer),
        )
        .map_err(|e| Error::WasmError(format!("process_decryption failed: {}", e)))?;

    if status != 0 {
        let _ = vsc_buffer_delete.call(&mut *helper.store, process_buffer);
        let _ = vscf_recipient_cipher_delete.call(&mut *helper.store, recipient_cipher);
        let _ = vscf_key_provider_delete.call(&mut *helper.store, key_provider);
        let _ = vscf_ctr_drbg_delete.call(&mut *helper.store, rng);
        return Err(Error::WasmError(format!(
            "process_decryption failed: {}",
            status
        )));
    }

    // Finish decryption
    let finish_out_len = vscf_recipient_cipher_decryption_out_len
        .call(&mut *helper.store, (recipient_cipher, 0))
        .map_err(|e| Error::WasmError(format!("decryption_out_len failed: {}", e)))?;

    let finish_buffer_size = (finish_out_len.max(64)).min(10000);
    let finish_buffer = vsc_buffer_new_with_capacity
        .call(&mut *helper.store, finish_buffer_size)
        .map_err(|e| Error::WasmError(format!("buffer_new failed: {}", e)))?;

    let status = vscf_recipient_cipher_finish_decryption
        .call(&mut *helper.store, (recipient_cipher, finish_buffer))
        .map_err(|e| Error::WasmError(format!("finish_decryption failed: {}", e)))?;

    if status != 0 {
        let _ = vsc_buffer_delete.call(&mut *helper.store, finish_buffer);
        let _ = vsc_buffer_delete.call(&mut *helper.store, process_buffer);
        let _ = vscf_recipient_cipher_delete.call(&mut *helper.store, recipient_cipher);
        let _ = vscf_key_provider_delete.call(&mut *helper.store, key_provider);
        let _ = vscf_ctr_drbg_delete.call(&mut *helper.store, rng);
        return Err(Error::WasmError(format!(
            "finish_decryption failed: {}",
            status
        )));
    }

    // Combine output from process and finish buffers
    let process_ptr = vsc_buffer_bytes
        .call(&mut *helper.store, process_buffer)
        .map_err(|e| Error::WasmError(format!("buffer_bytes failed: {}", e)))?;
    let process_len = vsc_buffer_len
        .call(&mut *helper.store, process_buffer)
        .map_err(|e| Error::WasmError(format!("buffer_len failed: {}", e)))?;
    let finish_ptr = vsc_buffer_bytes
        .call(&mut *helper.store, finish_buffer)
        .map_err(|e| Error::WasmError(format!("buffer_bytes failed: {}", e)))?;
    let finish_len = vsc_buffer_len
        .call(&mut *helper.store, finish_buffer)
        .map_err(|e| Error::WasmError(format!("buffer_len failed: {}", e)))?;

    let mut decrypted = Vec::new();
    if process_len > 0 {
        decrypted.extend(helper.read_bytes(process_ptr, process_len)?);
    }
    if finish_len > 0 {
        decrypted.extend(helper.read_bytes(finish_ptr, finish_len)?);
    }

    // Cleanup
    let _ = vsc_buffer_delete.call(&mut *helper.store, finish_buffer);
    let _ = vsc_buffer_delete.call(&mut *helper.store, process_buffer);
    let _ = vscf_recipient_cipher_delete.call(&mut *helper.store, recipient_cipher);
    let _ = vscf_key_provider_delete.call(&mut *helper.store, key_provider);
    let _ = vscf_ctr_drbg_delete.call(&mut *helper.store, rng);

    if decrypted.is_empty() {
        return Err(Error::WasmError("Decryption produced no output".into()));
    }

    MobileKey::from_bytes(&decrypted)
}

/// Helper to get a typed WASM function.
fn get_func<P: WasmParams, R: WasmResults>(
    instance: &Instance,
    store: &mut Store<()>,
    name: &str,
) -> Result<TypedFunc<P, R>, Error> {
    instance
        .get_typed_func::<P, R>(store, name)
        .map_err(|e| Error::WasmError(format!("Failed to get WASM function '{}': {}", name, e)))
}
