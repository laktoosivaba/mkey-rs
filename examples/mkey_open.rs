use mkey::{MobileKey, OpeningMode};
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mkey_tlv = env::var("SALTO_MKEY_TLV")?;

    let mkey_bytes = hex::decode(&mkey_tlv)?;
    let mobile_key = MobileKey::from_bytes(&mkey_bytes)?;

    let outcome = mkey::sdk::open(
        mobile_key,
        None,
        OpeningMode::Standard,
        Some(Duration::from_secs(30)),
    )
    .await?;

    println!(
        "v0{}00: {} ({}), {}",
        outcome.protocol_version,
        outcome.op_result_name(),
        outcome
            .op_result
            .map(|r| r.to_string())
            .unwrap_or_else(|| "no result".to_string()),
        outcome.group
    );

    if !outcome.accepted {
        std::process::exit(1);
    }

    Ok(())
}
