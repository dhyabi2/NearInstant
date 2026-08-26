//! Emit a valid settlement transcript to `argv[1]` using the public
//! transcript API — a fixture for exercising the `swap-verify` CLI against a
//! real hash-chained file (and its tamper detection).

use swap_executor::transcript::{SwapManifest, Transcript};

fn main() {
    let path = std::env::args().nth(1).expect("usage: demo_transcript <out.jsonl>");
    let m = SwapManifest {
        version: 1,
        nano_account: [0xA1; 32],
        xmr_address: "56JointStagenetAddressExample".into(),
        chunk: 100_000_000_000,
        adaptor_point: [0xB2; 32],
        bob_dest: [0xC3; 32],
        open_link: [0xD4; 32],
        rung_hash: [0xE5; 32],
        claim_hash: [0xF6; 32],
    };
    let mut t = Transcript::start(std::path::Path::new(&path), &m).expect("start");
    t.record("funded", serde_json::json!({ "open_hash": "d4".repeat(32) })).unwrap();
    t.record("presigned", serde_json::json!({
        "r_adapted": "01".repeat(32), "adaptor_point": "b2".repeat(32),
    })).unwrap();
    t.record("claim-observed", serde_json::json!({
        "claim_hash": "f6".repeat(32), "signature": "77".repeat(64),
    })).unwrap();
    t.record("secret-extracted", serde_json::json!({ "x": "42".repeat(32) })).unwrap();
    t.record("swept", serde_json::json!({ "xmr_address": m.xmr_address })).unwrap();
    eprintln!("wrote {path}");
}
