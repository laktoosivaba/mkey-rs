# mkey-rs

A Rust library for opening SaltoKS locks using Digital Key/Mobile Key feature.  
The Rust implementation is reverse engineered from [the original vendor sdk](https://github.com/laktoosivaba/ourclay) obfuscated java code (LLMs involved).

## Features

- Complete SALTO protocol stack (BLE transport, SSP encryption, Justin command layer)
- Opening salto locks with Digital key via BLE
- Decoding `mkey_data` into plain TLV using Virgil crypto WASM

## TODOs

- [ ] Implement keychain and keygen for SaltoKS mkey registration

## Tested locks

- [SALTO Neoxx G4](https://saltosystems.com/en/products/salto-neoxx-padlock-g4/)
- SALTO XS4 Original (with Keypad)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
mkey = { path = "path/to/mkey-rs", features = ["sdk"] }
tokio = { version = "1", features = ["full"] }
```

### Feature flags

| Feature | Description |
|---------|-------------|
| `sdk` | High-level `sdk::open()` entry point |
| `sdk-virgil` | Virgil crypto decryption support (includes `sdk`) |

## Quick Start

Using the high-level SDK (requires `sdk` feature):

```rust
use mkey::{MobileKey, OpeningMode};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), mkey::Error> {
    let mobile_key = MobileKey::from_hex("c0020100c1...")?;

    mkey::sdk::open(
        mobile_key,
        None,                             // optional lock name filter
        OpeningMode::Standard,            // or OpeningMode::Office
        Some(Duration::from_secs(30)),    // scan timeout
    )
    .await?;

    Ok(())
}
```

Using the low-level API directly:

```rust
use mkey::{MobileKey, SaltoLock, OpeningMode};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), mkey::Error> {
    let mobile_key = MobileKey::from_bytes(&bytes)?;

    let mut lock = SaltoLock::new().await?;
    lock.scan_and_connect(Some(Duration::from_secs(10))).await?;
    lock.authenticate(mobile_key).await?;
    lock.open_with_mode(OpeningMode::Standard).await?;
    lock.disconnect().await?;

    Ok(())
}
```

## Running the Examples

```bash
cp .env.example .env

cargo run --example mkey_open --features sdk

cargo run --example mkey_decode --features sdk-virgil
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SALTO_MKEY_TLV` | For `mkey_open` | Hex-encoded mobile key TLV data |
| `SALTO_MKEY_DATA` | For `mkey_decode` | Base64-encoded Virgil encrypted mobile key |

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
