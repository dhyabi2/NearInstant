//! Differential test: state-block hashes against an independent Python
//! implementation, plus one real mainnet block vector.

use std::io::Write;
use std::process::{Command, Stdio};

use nano_ceremony::block::{StateBlock, Subtype};
use nano_ceremony::Bytes32;

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

#[test]
fn block_hash_agrees_with_python_reference() {
    let mut vectors = Vec::new();
    // Structured sweep: varied balances (0, 1, max), zero/nonzero fields.
    let cases: [(Bytes32, Bytes32, Bytes32, u128, Bytes32); 5] = [
        ([0; 32], [0; 32], [0; 32], 0, [0; 32]),
        ([1; 32], [2; 32], [3; 32], 1, [4; 32]),
        ([0xFF; 32], [0xEE; 32], [0xDD; 32], u128::MAX, [0xCC; 32]),
        ([9; 32], [0; 32], [9; 32], 340_282_366_920_938, [7; 32]),
        ([5; 32], [6; 32], [5; 32], 1_000_000_000_000_000_000_000_000_000_000, [0; 32]),
    ];
    for (account, previous, representative, balance, link) in cases {
        let b = StateBlock {
            account,
            previous,
            representative,
            balance,
            link,
            subtype: Subtype::Send,
        };
        vectors.push(format!(
            r#"{{"account":"{}","previous":"{}","representative":"{}","balance":"{}","link":"{}","expect":"{}"}}"#,
            hx(&account),
            hx(&previous),
            hx(&representative),
            balance,
            hx(&link),
            hx(&b.hash())
        ));
    }

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/block_hash_ref.py");
    let mut child = Command::new("python3")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn python3");
    {
        let stdin = child.stdin.as_mut().unwrap();
        for v in &vectors {
            writeln!(stdin, "{v}").unwrap();
        }
    }
    let out = child.wait_with_output().expect("python3 runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "python disagreed: {stdout}");
    assert!(stdout.contains(&format!("OK {}", vectors.len())), "{stdout}");
}

/// A real confirmed mainnet state block, fetched from a public node
/// (`block_info` on FC43263810D94A548BBC9A4D6A21D0E754D885BF670F1F886C3778
/// F7C43E60AE): our hash must match the network's, our address decoding must
/// reproduce the link account, our verifier must accept the live network
/// signature, and the attached work must validate at the send threshold.
#[test]
fn mainnet_state_block_vector() {
    let account = nano_ceremony::address::decode(
        "nano_1qato4k7z3spc8gq1zyd8xeqfbzsoxwo36a45ozbrxcatut7up8ohyardu1z",
    )
    .expect("valid address");
    let previous: Bytes32 =
        hex::decode("6F18604D3074437C23E3480E74D8FBB2C48ABEE02BC2E9F109A89C401A4325D6")
            .unwrap()
            .try_into()
            .unwrap();
    let representative = nano_ceremony::address::decode(
        "nano_3pczxuorp48td8645bs3m6c3xotxd3idskrenmi65rbrga5zmkemzhwkaznh",
    )
    .expect("valid address");
    let link: Bytes32 =
        hex::decode("E1368DE83E35A8430738E7FE256A0768F58C7843632D76F9735AFDC6CAA1BB1D")
            .unwrap()
            .try_into()
            .unwrap();
    assert_eq!(
        nano_ceremony::address::encode(&link),
        "nano_3rbpjqn5wffaae5mjszy6oo1gt9ojjw68rsfguwq8pqxru7c5grxtkzc84s4"
    );
    let b = StateBlock {
        account,
        previous,
        representative,
        balance: 567_890_000_000_000_000_000_000,
        link,
        subtype: Subtype::Send,
    };
    assert_eq!(
        hex::encode_upper(b.hash()),
        "FC43263810D94A548BBC9A4D6A21D0E754D885BF670F1F886C3778F7C43E60AE"
    );

    // The live network signature verifies under our independent verifier.
    let signature: [u8; 64] = hex::decode(
        "910FE32DBF96BF3185227B0A3C41C6E71640E5E1AB9EC6DD8278BCFB25570921\
         A0326965582CA79CBDD23D19BD43004019CEB60CE757D997D559E39F62410409",
    )
    .unwrap()
    .try_into()
    .unwrap();
    assert!(signing::nano_verify::verify(&account, &b.hash(), &signature));

    // The live work value validates at the threshold of its era (this block
    // is from 2019, before the epoch-v2 difficulty raise) and, like all v1
    // work, falls short of the current send threshold.
    let work = u64::from_str_radix("bf28f6851d931c3e", 16).unwrap();
    assert!(nano_ceremony::work::validate(
        &b.work_root(),
        work,
        nano_ceremony::work::THRESHOLD_EPOCH_V1
    ));
    assert!(!nano_ceremony::work::validate(
        &b.work_root(),
        work,
        nano_ceremony::work::THRESHOLD_SEND
    ));
}
