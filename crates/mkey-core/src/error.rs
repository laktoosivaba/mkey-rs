use thiserror::Error;

/// The shared failure vocabulary.
///
/// One value per `SaltoErrorCode` in the TypeScript port
/// (`mkey-js/src/errors.ts`). This is the contract the application layer
/// matches on, so the two implementations have to agree on it exactly — the
/// conformance fixtures record these very strings.
///
/// Rust does not raise every one of them today (`Security` has no producer
/// outside the browser, for instance), but the vocabulary is shared whole:
/// a code that exists on one side and not the other is a contract that drifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    Aborted,
    AuthenticationFailed,
    BluetoothUnavailable,
    CharacteristicNotFound,
    ConnectionFailed,
    DeviceNotFound,
    Disconnected,
    GattOperationFailed,
    InvalidCrc,
    InvalidData,
    InvalidPadding,
    InvalidState,
    Security,
    ServiceNotFound,
    Timeout,
    UnsupportedProtocol,
    UserCancelled,
}

impl ErrorCode {
    /// Every code, in the order `SaltoErrorCode` lists them.
    pub const ALL: [ErrorCode; 17] = [
        Self::Aborted,
        Self::AuthenticationFailed,
        Self::BluetoothUnavailable,
        Self::CharacteristicNotFound,
        Self::ConnectionFailed,
        Self::DeviceNotFound,
        Self::Disconnected,
        Self::GattOperationFailed,
        Self::InvalidCrc,
        Self::InvalidData,
        Self::InvalidPadding,
        Self::InvalidState,
        Self::Security,
        Self::ServiceNotFound,
        Self::Timeout,
        Self::UnsupportedProtocol,
        Self::UserCancelled,
    ];

    /// The wire spelling, identical to the TypeScript union member.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aborted => "aborted",
            Self::AuthenticationFailed => "authentication-failed",
            Self::BluetoothUnavailable => "bluetooth-unavailable",
            Self::CharacteristicNotFound => "characteristic-not-found",
            Self::ConnectionFailed => "connection-failed",
            Self::DeviceNotFound => "device-not-found",
            Self::Disconnected => "disconnected",
            Self::GattOperationFailed => "gatt-operation-failed",
            Self::InvalidCrc => "invalid-crc",
            Self::InvalidData => "invalid-data",
            Self::InvalidPadding => "invalid-padding",
            Self::InvalidState => "invalid-state",
            Self::Security => "security",
            Self::ServiceNotFound => "service-not-found",
            Self::Timeout => "timeout",
            Self::UnsupportedProtocol => "unsupported-protocol",
            Self::UserCancelled => "user-cancelled",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("BLE connection failed: {0}")]
    ConnectionFailed(String),

    #[error("No Bluetooth adapter available")]
    BluetoothUnavailable,

    #[error("BLE disconnected unexpectedly")]
    Disconnected,

    #[error("Service not found: {0}")]
    ServiceNotFound(String),

    #[error("Characteristic not found: {0}")]
    CharacteristicNotFound(String),

    /// A platform GATT call failed. The transport puts the platform's own
    /// message inside, the way `toGattError` does in the browser port.
    #[error("{0}")]
    GattOperationFailed(String),

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

    #[error("Hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),

    #[error("TLV parse error: {0}")]
    TlvError(String),
}

impl Error {
    /// The [`ErrorCode`] this failure reports to the application.
    ///
    /// Several distinct failures share a code on purpose: the application can
    /// only act on the category, and the message carries the detail.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::ConnectionFailed(_) => ErrorCode::ConnectionFailed,
            Self::BluetoothUnavailable => ErrorCode::BluetoothUnavailable,
            Self::Disconnected => ErrorCode::Disconnected,
            Self::ServiceNotFound(_) => ErrorCode::ServiceNotFound,
            Self::CharacteristicNotFound(_) => ErrorCode::CharacteristicNotFound,
            Self::GattOperationFailed(_) => ErrorCode::GattOperationFailed,
            Self::AuthenticationFailed => ErrorCode::AuthenticationFailed,
            Self::InvalidCrc => ErrorCode::InvalidCrc,
            Self::InvalidPadding => ErrorCode::InvalidPadding,
            Self::InvalidProtocolVersion(_) => ErrorCode::UnsupportedProtocol,
            Self::InvalidState { .. } => ErrorCode::InvalidState,
            Self::Timeout(_) => ErrorCode::Timeout,
            Self::NoLocksFound => ErrorCode::DeviceNotFound,
            Self::Cancelled => ErrorCode::Aborted,

            // Everything that means "the bytes did not say what they should".
            Self::DecryptionFailed
            | Self::CommandFailed(_)
            | Self::InvalidMobileKey
            | Self::KeyNotFound(_)
            | Self::InvalidKeyLength(_)
            | Self::InvalidData(_)
            | Self::HexError(_)
            | Self::TlvError(_) => ErrorCode::InvalidData,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CommandStatus {
    Success = 0x00,
    GenericError = 0x01,
    NotFound = 0x02,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SaltoErrorCode` from `mkey-js/src/errors.ts`, copied verbatim.
    ///
    /// If this list and [`ErrorCode`] ever disagree, one implementation is
    /// reporting a failure the other cannot name.
    const TYPESCRIPT_UNION: [&str; 17] = [
        "aborted",
        "authentication-failed",
        "bluetooth-unavailable",
        "characteristic-not-found",
        "connection-failed",
        "device-not-found",
        "disconnected",
        "gatt-operation-failed",
        "invalid-crc",
        "invalid-data",
        "invalid-padding",
        "invalid-state",
        "security",
        "service-not-found",
        "timeout",
        "unsupported-protocol",
        "user-cancelled",
    ];

    #[test]
    fn the_code_vocabulary_matches_the_typescript_union() {
        let ours: Vec<&str> = ErrorCode::ALL.iter().map(|code| code.as_str()).collect();

        assert_eq!(ours, TYPESCRIPT_UNION);
    }

    #[test]
    fn every_error_reports_a_code_in_the_vocabulary() {
        let errors = [
            Error::ConnectionFailed(String::new()),
            Error::BluetoothUnavailable,
            Error::Disconnected,
            Error::ServiceNotFound(String::new()),
            Error::CharacteristicNotFound(String::new()),
            Error::GattOperationFailed(String::new()),
            Error::AuthenticationFailed,
            Error::DecryptionFailed,
            Error::InvalidCrc,
            Error::InvalidPadding,
            Error::InvalidProtocolVersion(String::new()),
            Error::CommandFailed(CommandStatus::GenericError),
            Error::InvalidState {
                expected: String::new(),
                actual: String::new(),
            },
            Error::InvalidMobileKey,
            Error::KeyNotFound(String::new()),
            Error::InvalidKeyLength(0),
            Error::Timeout(0),
            Error::NoLocksFound,
            Error::Cancelled,
            Error::InvalidData(String::new()),
            Error::HexError(hex::FromHexError::OddLength),
            Error::TlvError(String::new()),
        ];

        for error in &errors {
            assert!(
                ErrorCode::ALL.contains(&error.code()),
                "{error:?} reports a code outside the vocabulary"
            );
        }
    }
}
