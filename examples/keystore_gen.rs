//! Generate a fresh keystore for registering a device with the SaltoKS API.
//!
//! ```text
//! cargo run --example keystore_gen --features sdk-virgil -- [--out DIR] [--force]
//! ```
//!
//! Writes (all `0600` on Unix):
//!
//! | file | contents |
//! |------|----------|
//! | `private_key.der`         | RSA-2048 wrapping key, PKCS#8 DER |
//! | `sdk.txt`                 | base64 of `RSA_PKCS1v15(base64(SEC1 EC key))` |
//! | `virgil_private_sec1.der` | Virgil EC private key, SEC1 DER (plaintext copy) |
//! | `virgil_public_spki.der`  | EC public key, SPKI DER |
//! | `virgil_public_key.b64`   | base64 of the SPKI — this is what SaltoKS registers |
//! | `virgil_public_key.pem`   | same key, PEM |
//!
//! Only the public key is printed; nothing secret reaches stdout.

use base64::Engine as _;
use mkey::sdk::{encrypt_virgil_private_key, generate_rsa_private_key, generate_virgil_key_pair};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const RSA_PRIVATE_KEY: &str = "private_key.der";
const SDK_TXT: &str = "sdk.txt";
const VIRGIL_PRIVATE_SEC1: &str = "virgil_private_sec1.der";
const VIRGIL_PUBLIC_SPKI: &str = "virgil_public_spki.der";
const VIRGIL_PUBLIC_B64: &str = "virgil_public_key.b64";
const VIRGIL_PUBLIC_PEM: &str = "virgil_public_key.pem";

const USAGE: &str = "\
usage: keystore_gen [--out DIR] [--force]

  --out DIR   keystore directory to create (default: keystore)
  --force     overwrite a non-empty directory
";

struct Args {
    out: PathBuf,
    force: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut out = PathBuf::from("keystore");
    let mut force = false;
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--out" => {
                out = PathBuf::from(argv.next().ok_or("--out needs a directory")?);
            }
            "--force" => force = true,
            "-h" | "--help" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {}", other)),
        }
    }
    Ok(Args { out, force })
}

/// Write a keystore file, restricting it to the owner on Unix.
fn write_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
        file.flush()?;
        // `mode` only applies to freshly created files; with --force the file
        // may already exist with looser permissions.
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut file = fs::File::create(path)?;
        file.write_all(data)?;
        file.flush()
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {}-----\n", label);
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {}-----\n", label));
    out
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args().unwrap_or_else(|e| {
        eprintln!("{}\n\n{}", e, USAGE);
        std::process::exit(2);
    });

    if args.out.exists() && args.out.read_dir()?.next().is_some() && !args.force {
        eprintln!(
            "{} already exists and is not empty; refusing to overwrite (use --force)",
            args.out.display()
        );
        std::process::exit(1);
    }
    fs::create_dir_all(&args.out)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&args.out, fs::Permissions::from_mode(0o700))?;
    }

    println!("Generating RSA-2048 wrapping key…");
    let rsa_private_key_der = generate_rsa_private_key()?;

    println!("Generating Virgil SECP256R1 key pair…");
    let pair = generate_virgil_key_pair()?;

    let sdk_blob = encrypt_virgil_private_key(&rsa_private_key_der, &pair.private_key_der)?;
    let sdk_b64 = base64::engine::general_purpose::STANDARD.encode(&sdk_blob);
    let public_b64 = base64::engine::general_purpose::STANDARD.encode(&pair.public_key_der);

    let files: [(&str, Vec<u8>); 6] = [
        (RSA_PRIVATE_KEY, rsa_private_key_der),
        (SDK_TXT, format!("{}\n", sdk_b64).into_bytes()),
        (VIRGIL_PRIVATE_SEC1, pair.private_key_der.clone()),
        (VIRGIL_PUBLIC_SPKI, pair.public_key_der.clone()),
        (VIRGIL_PUBLIC_B64, format!("{}\n", public_b64).into_bytes()),
        (
            VIRGIL_PUBLIC_PEM,
            pem("PUBLIC KEY", &pair.public_key_der).into_bytes(),
        ),
    ];

    println!("\nWrote {}:", args.out.display());
    for (name, data) in &files {
        write_file(&args.out.join(name), data)?;
        println!("  {:<24} {} bytes", name, data.len());
    }

    println!("\nDevice public key (base64 SPKI) — register this with the SaltoKS API:");
    println!("{}", public_b64);
    println!(
        "\nThen decode the returned mkey_data:\n  \
         SALTO_MKEY_DATA=<base64> cargo run --example mkey_decode --features sdk-virgil"
    );
    Ok(())
}
