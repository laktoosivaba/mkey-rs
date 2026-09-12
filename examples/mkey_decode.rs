use base64::Engine as B64Engine;
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    println!("=== Virgil Crypto MKey Decryption ===\n");

    // Load RSA private key (PKCS8 DER)
    let rsa_key_der = fs::read("keystore/private_key.der")?;
    println!("Loaded RSA private key: {} bytes", rsa_key_der.len());

    // Load encrypted Virgil EC key
    let encrypted_virgil_key_b64 = fs::read_to_string("keystore/sdk.txt")?;
    let encrypted_virgil_key =
        base64::engine::general_purpose::STANDARD.decode(encrypted_virgil_key_b64.trim())?;
    println!("Encrypted Virgil key: {} bytes", encrypted_virgil_key.len());

    // Load encrypted mkey data
    let mkey_b64 = env::var("SALTO_MKEY_DATA")?;
    let encrypted_mkey_data = base64::engine::general_purpose::STANDARD.decode(&mkey_b64)?;
    println!("Encrypted mkey data: {} bytes", encrypted_mkey_data.len());

    // Decode the mobile key
    let mobile_key = mkey::sdk::decode(&rsa_key_der, &encrypted_virgil_key, &encrypted_mkey_data)?;

    println!("\n=== Decrypted SALTO Mobile Key ===");
    println!("  kn_key: {}", hex::encode(mobile_key.kn_key));
    println!("  tag_0: {}", hex::encode(&mobile_key.tag_0));
    println!("  tag_1: {} bytes", mobile_key.tag_1.len());
    println!("  tags: {:?}", mobile_key.tags.keys().collect::<Vec<_>>());
    for (id, tag) in &mobile_key.tags {
        println!(
            "    Tag 0x{:02X}: perms=0x{:02X}, value={:02X?}",
            id,
            tag.permissions.flags(),
            tag.value
        );
    }

    println!("\nTLV hex: {}", mobile_key.to_hex());
    println!("\n=== Done ===");

    Ok(())
}
