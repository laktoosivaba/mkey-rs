use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("BLE connection failed: {0}")]
    ConnectionFailed(String),

    #[error("BLE disconnected unexpectedly")]
    Disconnected,

    #[error("Service not found: {0}")]
    ServiceNotFound(String),

    #[error("Characteristic not found: {0}")]
    CharacteristicNotFound(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid CRC checksum")]
    InvalidCrc,

    #[error("Invalid padding")]
    InvalidPadding,

    #[error("Invalid protocol version: {0}")]
    InvalidProtocolVersion(String),

    #[error("Command failed with status: {0:?}")]
    CommandFailed(CommandStatus),

    #[error("Invalid state for operation: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },

    #[error("Invalid mobile key data")]
    InvalidMobileKey,

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid key length: expected 16, got {0}")]
    InvalidKeyLength(usize),

    #[error("Operation timeout after {0}ms")]
    Timeout(u64),

    #[error("No SALTO locks found")]
    NoLocksFound,

    #[error("Operation cancelled")]
    Cancelled,

    #[error("Invalid data received: {0}")]
    InvalidData(String),

    #[error("BLE error: {0}")]
    BleError(#[from] btleplug::Error),

    #[error("Hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),

    #[error("TLV parse error: {0}")]
    TlvError(String),

    #[error("Virgil container error: {0}")]
    VirgilContainerError(String),

    #[error("RSA decryption error: {0}")]
    RsaDecryptionError(String),

    #[error("WASM runtime error: {0}")]
    WasmError(String),
}

#[derive(Debug, Clone, Copy)]
pub enum CommandStatus {
    Success = 0x00,
    GenericError = 0x01,
    NotFound = 0x02,
}
