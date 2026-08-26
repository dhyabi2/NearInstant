//! `swap-verify` — the stranger's tool (R11): verify a published settlement
//! transcript OFFLINE, in seconds, without trusting the operator.
//!
//!   swap-verify <transcript.jsonl> [<counterparty-transcript.jsonl>]
//!
//! One file: checks the hash chain (no line edited, dropped, or reordered)
//! and the manifest's embedded hash, then prints the settlement facts — the
//! joint accounts, the claim hash to look up on any Nano explorer/node, the
//! Monero address to check for the lock + sweep.
//!
//! Two files: additionally proves the two parties computed the IDENTICAL
//! pre-funding manifest — the agreement existed before funds moved.
//!
//! Exit code 0 = VALID, 1 = INVALID, 2 = usage. No network access, ever.

use swap_executor::transcript::{verify, Event, TranscriptError};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.len() > 2 {
        eprintln!("usage: swap-verify <transcript.jsonl> [<counterparty-transcript.jsonl>]");
        std::process::exit(2);
    }

    let first = check_file(&args[0]);
    if args.len() == 2 {
        let second = check_file(&args[1]);
        let (Some(a), Some(b)) = (manifest_hash(&first), manifest_hash(&second)) else {
            eprintln!("INVALID: a transcript is missing its manifest hash");
            std::process::exit(1);
        };
        if a == b {
            println!("MANIFESTS MATCH: both parties agreed on {a} before funds moved");
        } else {
            eprintln!("INVALID: manifests differ ({a} vs {b}) — the parties did NOT agree");
            std::process::exit(1);
        }
    }
    println!("VALID");
}

fn check_file(path: &str) -> Vec<Event> {
    let contents = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("INVALID: cannot read {path}: {e}");
        std::process::exit(1);
    });
    match verify(&contents) {
        Ok(events) => {
            println!("── {path}: chain of {} events intact", events.len());
            for e in &events {
                println!("   {:>2}. {}", e.seq, describe(e));
            }
            events
        }
        Err(err) => {
            let why = match err {
                TranscriptError::Malformed(n) => format!("line {n} is malformed"),
                TranscriptError::BrokenChain(n) => {
                    format!("hash chain BREAKS at line {n} (edited, dropped, or reordered)")
                }
                TranscriptError::BadManifest => "manifest line missing or its hash is wrong".into(),
                TranscriptError::Empty => "file is empty".into(),
            };
            eprintln!("INVALID: {path}: {why}");
            std::process::exit(1);
        }
    }
}

fn manifest_hash(events: &[Event]) -> Option<String> {
    events
        .first()?
        .data
        .get("manifest_hash")?
        .as_str()
        .map(str::to_string)
}

/// One line of plain English per step, surfacing the publicly checkable facts.
fn describe(e: &Event) -> String {
    let g = |k: &str| e.data.get(k).and_then(|v| v.as_str()).unwrap_or("?").to_string();
    match e.step.as_str() {
        "manifest" => {
            let m = e.data.get("manifest");
            let f = |k: &str| {
                m.and_then(|m| m.get(k))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string()
            };
            format!(
                "manifest {} — joint Nano acct {}…, joint XMR addr {}…, chunk {}, claim {}",
                g("manifest_hash"),
                &f("nano_account")[..16.min(f("nano_account").len())],
                &f("xmr_address")[..16.min(f("xmr_address").len())],
                f("chunk"),
                f("claim_hash"),
            )
        }
        "funded" => format!("joint account funded (pending send {})", g("open_hash")),
        "presigned" => format!("adaptor pre-signature bound to T={}", g("adaptor_point")),
        "locked" => format!("XMR locked to {} ({} piconero)", g("xmr_address"), g("chunk")),
        "cosigned-open" => format!("open block co-signed ({})", g("open_hash")),
        "rung-confirmed" => format!("guard rung confirmed on quorum ({})", g("rung_hash")),
        "claim-broadcast" => format!("claim broadcast — secret revealed on-chain ({})", g("claim_hash")),
        "claim-observed" => format!("claim observed on-chain ({})", g("claim_hash")),
        "secret-extracted" => format!("secret extracted from the claim signature (x={})", g("x")),
        "swept" => format!("joint XMR swept from {}", g("xmr_address")),
        other => format!("{other}: {}", e.data),
    }
}
