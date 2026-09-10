//! Verify a keystore produced by `keystore_gen` (or by the vendor SDK).
//!
//! ```text
//! cargo run --example keystore_check --features sdk-virgil -- [--dir DIR]
//! ```
//!
//! Walks the exact key path `mkey_decode` uses — RSA-unwrap `sdk.txt`, import
//! the SEC1 key into Virgil, derive its public key — and compares the result
//! with `virgil_public_spki.der`. Exits 1 on any mismatch. Prints lengths and
//! the public key only.

use base64::Engine as _;
use mkey::sdk::{
    decrypt_virgil_private_key, derive_virgil_public_key, roundtrip_virgil_public_key,
};
use std::fs;
use std::path::PathBuf;

const USAGE: &str = "\
usage: keystore_check [--dir DIR]

  --dir DIR   keystore directory to verify (default: keystore)
";

fn parse_dir() -> Result<PathBuf, String> {
    let mut dir = PathBuf::from("keystore");
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--dir" => dir = PathBuf::from(argv.next().ok_or("--dir needs a directory")?),
            "-h" | "--help" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {}", other)),
        }
    }
    Ok(dir)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = parse_dir().unwrap_or_else(|e| {
        eprintln!("{}\n\n{}", e, USAGE);
        std::process::exit(2);
    });
    println!("Checking keystore at {}", dir.display());

    let rsa_private_key_der = fs::read(dir.join("private_key.der"))?;
    let sdk_b64 = fs::read_to_string(dir.join("sdk.txt"))?;
    let sdk_blob = base64::engine::general_purpose::STANDARD.decode(sdk_b64.trim())?;
    let public_spki = fs::read(dir.join("virgil_public_spki.der"))?;

    println!(
        "  private_key.der          {} bytes",
        rsa_private_key_der.len()
    );
    println!(
        "  sdk.txt                  {} bytes (decoded)",
        sdk_blob.len()
    );
    println!("  virgil_public_spki.der   {} bytes", public_spki.len());

    // 1. RSA-unwrap the Virgil private key, exactly as `sdk::decode` does.
    let private_key_der = decrypt_virgil_private_key(&rsa_private_key_der, &sdk_blob)?;
    println!(
        "\n  RSA unwrap:              OK, {} byte SEC1 private key",
        private_key_der.len()
    );

    // 2. If the plaintext copy is present, it must agree with the unwrapped one.
    let sec1_path = dir.join("virgil_private_sec1.der");
    let sec1_matches = if sec1_path.exists() {
        let stored = fs::read(&sec1_path)?;
        let ok = stored == private_key_der;
        println!(
            "  virgil_private_sec1.der: {} bytes, matches sdk.txt: {}",
            stored.len(),
            ok
        );
        ok
    } else {
        println!("  virgil_private_sec1.der: absent (skipped)");
        true
    };

    // 3. Import into Virgil and derive the public key.
    let derived = derive_virgil_public_key(&private_key_der)?;
    let derived_matches = derived == public_spki;
    println!(
        "  Virgil import + derive:  OK, {} byte SPKI, matches virgil_public_spki.der: {}",
        derived.len(),
        derived_matches
    );

    // 4. The stored public key must itself be one Virgil accepts.
    let roundtrip = roundtrip_virgil_public_key(&public_spki)?;
    let roundtrip_matches = roundtrip == public_spki;
    println!("  Public key round trip:   {}", roundtrip_matches);

    println!(
        "\n  Public key (base64 SPKI): {}",
        base64::engine::general_purpose::STANDARD.encode(&derived)
    );

    if sec1_matches && derived_matches && roundtrip_matches {
        println!("\nOK — keystore is consistent and usable for mkey_decode.");
        Ok(())
    } else {
        println!("\nFAIL — keystore is inconsistent; mkey_decode would not work.");
        std::process::exit(1);
    }
}
