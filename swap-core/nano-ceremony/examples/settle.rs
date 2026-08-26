//! Real-settlement helper: build and sign Nano state blocks with OUR stack
//! (`nano-ceremony` + `signing`, ed25519-blake2b) so a real `nano_node` can
//! validate and confirm them. Used to demonstrate the Nano leg settling on a
//! real dev-network node. Work is supplied externally (the node's
//! `work_generate`), matching the N4 "any work provider" property.
//!
//!   settle keygen
//!       → prints  PRIV=<hex>  ACCOUNT=<nano_...>  PUB=<hex>
//!
//!   settle receive <priv_hex> <source_send_hash> <amount_raw> <representative_nano>
//!       → prints the block hash, signature, and a JSON `contents` object
//!         (without work); the caller attaches work and calls `process`.

use nano_ceremony::block::{StateBlock, Subtype};
use nano_ceremony::{address, Bytes32};
use signing::{SigningKey, VerifyingKey};

fn hexb(b: &[u8]) -> String {
    hex::encode_upper(b)
}

fn parse32(s: &str) -> Bytes32 {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => {
            let key = SigningKey::new(&mut rand::rngs::OsRng);
            let pub_bytes: Bytes32 = VerifyingKey::from(&key)
                .serialize()
                .unwrap()
                .try_into()
                .unwrap();
            let priv_bytes = key.serialize();
            println!("PRIV={}", hexb(&priv_bytes));
            println!("PUB={}", hexb(&pub_bytes));
            println!("ACCOUNT={}", address::encode(&pub_bytes));
        }
        Some("receive") => {
            // settle receive <priv> <source_hash> <amount_raw> <rep_nano>
            let key = SigningKey::deserialize(&hex::decode(&args[2]).unwrap()).unwrap();
            let pub_bytes: Bytes32 = VerifyingKey::from(&key)
                .serialize()
                .unwrap()
                .try_into()
                .unwrap();
            let source = parse32(&args[3]);
            let amount: u128 = args[4].parse().unwrap();
            let representative = address::decode(&args[5]).expect("rep address");

            // First block of the account: open/receive. previous = 0,
            // link = the source send hash, balance = amount.
            let block = StateBlock {
                account: pub_bytes,
                previous: [0u8; 32],
                representative,
                balance: amount,
                link: source,
                subtype: Subtype::Open,
            };
            let hash = block.hash();
            let sig = key.sign(&mut rand::rngs::OsRng, &hash);
            let sig_bytes: [u8; 64] = sig.serialize().unwrap().try_into().unwrap();

            // Self-check with our independent verifier before emitting.
            assert!(
                signing::nano_verify::verify(&pub_bytes, &hash, &sig_bytes),
                "our own signature must verify"
            );

            println!("HASH={}", hexb(&hash));
            println!("WORKROOT={}", hexb(&block.work_root()));
            // JSON contents for the `process` RPC (work attached by caller).
            println!(
                "CONTENTS={{\"type\":\"state\",\"account\":\"{}\",\"previous\":\"{}\",\"representative\":\"{}\",\"balance\":\"{}\",\"link\":\"{}\",\"signature\":\"{}\"}}",
                address::encode(&pub_bytes),
                hexb(&[0u8; 32]),
                address::encode(&representative),
                amount,
                hexb(&source),
                hexb(&sig_bytes),
            );
        }
        _ => {
            eprintln!("usage: settle keygen | settle receive <priv> <src_hash> <amount> <rep>");
            std::process::exit(2);
        }
    }
}
