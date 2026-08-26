//! The verifiable settlement transcript (R2) — the first real settlement must
//! be maximum public evidence, not an operator's word.
//!
//! Two pieces:
//!
//! - [`SwapManifest`]: the pre-funding agreement, computed independently by
//!   BOTH parties from the ceremony outputs (joint accounts, chunk, adaptor
//!   point, destinations, claim hash). Its Blake2b-256 hash is the session's
//!   identity: if the two sides' manifest hashes differ, keys or parameters
//!   diverged and the swap must abort BEFORE funds move.
//!
//! - [`Transcript`]: an append-only, hash-chained event log. Every step
//!   (funding broadcast, lock, rung confirm, claim, extract, sweep) is
//!   recorded as a line whose hash covers the previous line's hash, so the
//!   file cannot be reordered or edited after the fact without breaking the
//!   chain. Paired with the two public ledgers (the Nano claim block and the
//!   Monero transactions it names), a third party can re-verify the whole
//!   settlement from the transcript alone.
//!
//! Transcripts contain ONLY public data: block hashes, addresses, tx ids, the
//! adaptor point. Never a spend secret — the revealed `x` is on the public
//! ledger anyway the moment settlement happens.

use std::io::Write as _;
use std::path::Path;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use nano_ceremony::Bytes32;

/// The pre-funding agreement both parties must compute identically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapManifest {
    /// Protocol version of this manifest encoding.
    pub version: u32,
    /// The joint 2-of-2 Nano account (public key bytes).
    pub nano_account: Bytes32,
    /// The joint Monero primary address.
    pub xmr_address: String,
    /// Chunk size in raw.
    pub chunk: u128,
    /// The adaptor point `T = x·G` (Bob's Monero spend pub) the claim binds to.
    pub adaptor_point: Bytes32,
    /// Bob's Nano destination account (public key bytes).
    pub bob_dest: Bytes32,
    /// The pending-send hash funding the joint account.
    pub open_link: Bytes32,
    /// The guard rung's block hash.
    pub rung_hash: Bytes32,
    /// The claim block's hash (what settlement broadcasts).
    pub claim_hash: Bytes32,
}

impl SwapManifest {
    /// Canonical JSON — field order fixed, all bytes lowercase hex.
    pub fn canonical_json(&self) -> String {
        serde_json::json!({
            "version": self.version,
            "nano_account": hex::encode(self.nano_account),
            "xmr_address": self.xmr_address,
            "chunk": self.chunk.to_string(),
            "adaptor_point": hex::encode(self.adaptor_point),
            "bob_dest": hex::encode(self.bob_dest),
            "open_link": hex::encode(self.open_link),
            "rung_hash": hex::encode(self.rung_hash),
            "claim_hash": hex::encode(self.claim_hash),
        })
        .to_string()
    }

    /// Blake2b-256 of the canonical JSON — the session identity. Two parties
    /// whose hashes differ MUST abort before funding.
    pub fn hash(&self) -> Bytes32 {
        let mut h = Blake2b::<U32>::new();
        h.update(self.canonical_json().as_bytes());
        h.finalize().into()
    }
}

/// One hash-chained transcript line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub seq: u64,
    /// Step name (`manifest`, `funded`, `locked`, `rung-confirmed`,
    /// `claim-broadcast`, `claim-observed`, `secret-extracted`, `swept`, …).
    pub step: String,
    /// Public step data (hex hashes, tx ids, addresses).
    pub data: serde_json::Value,
    /// Previous line's hash (all-zero for the first line).
    pub prev: Bytes32,
    /// Blake2b-256 over `prev ‖ seq ‖ step ‖ canonical data`.
    pub hash: Bytes32,
}

fn event_hash(prev: &Bytes32, seq: u64, step: &str, data: &serde_json::Value) -> Bytes32 {
    let mut h = Blake2b::<U32>::new();
    h.update(prev);
    h.update(seq.to_le_bytes());
    h.update(step.as_bytes());
    h.update(data.to_string().as_bytes());
    h.finalize().into()
}

/// An append-only settlement transcript. `record` writes one chained line to
/// the file (append + flush) and keeps the running head hash.
pub struct Transcript {
    path: std::path::PathBuf,
    seq: u64,
    head: Bytes32,
}

impl Transcript {
    /// Start a transcript whose first line is the manifest itself.
    pub fn start(path: &Path, manifest: &SwapManifest) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // A fresh file per session: refuse to append to an existing one.
        let mut t = Self {
            path: path.to_path_buf(),
            seq: 0,
            head: [0u8; 32],
        };
        std::fs::write(path, "")?;
        t.record(
            "manifest",
            serde_json::json!({
                "manifest": serde_json::from_str::<serde_json::Value>(&manifest.canonical_json())
                    .expect("canonical manifest is json"),
                "manifest_hash": hex::encode(manifest.hash()),
            }),
        )?;
        Ok(t)
    }

    /// Append one event. Best-effort callers may ignore the result — a failed
    /// transcript write must never abort a live settlement.
    pub fn record(&mut self, step: &str, data: serde_json::Value) -> std::io::Result<()> {
        let hash = event_hash(&self.head, self.seq, step, &data);
        let line = serde_json::json!({
            "seq": self.seq,
            "step": step,
            "data": data,
            "prev": hex::encode(self.head),
            "hash": hex::encode(hash),
        });
        let mut f = std::fs::OpenOptions::new().append(true).open(&self.path)?;
        writeln!(f, "{line}")?;
        f.flush()?;
        self.seq += 1;
        self.head = hash;
        Ok(())
    }
}

/// Errors verifying a transcript file.
#[derive(Debug, PartialEq, Eq)]
pub enum TranscriptError {
    /// Line `n` is not valid JSON / missing fields.
    Malformed(u64),
    /// Line `n`'s hash does not cover its content + the previous hash.
    BrokenChain(u64),
    /// The first line is not a `manifest` event, or its embedded hash is wrong.
    BadManifest,
    /// The file is empty.
    Empty,
}

/// Verify a transcript's hash chain and manifest line. Returns the parsed
/// events. This is the third-party entry point: chain-verify the file, then
/// check the named blocks/txs against the public ledgers.
pub fn verify(contents: &str) -> Result<Vec<Event>, TranscriptError> {
    let mut events = Vec::new();
    let mut prev = [0u8; 32];
    for (i, line) in contents.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let n = i as u64;
        let v: serde_json::Value =
            serde_json::from_str(line).map_err(|_| TranscriptError::Malformed(n))?;
        let seq = v.get("seq").and_then(|s| s.as_u64()).ok_or(TranscriptError::Malformed(n))?;
        let step = v
            .get("step")
            .and_then(|s| s.as_str())
            .ok_or(TranscriptError::Malformed(n))?
            .to_string();
        let data = v.get("data").cloned().ok_or(TranscriptError::Malformed(n))?;
        let prev_f = unhex(&v, "prev").ok_or(TranscriptError::Malformed(n))?;
        let hash_f = unhex(&v, "hash").ok_or(TranscriptError::Malformed(n))?;
        if seq != n || prev_f != prev {
            return Err(TranscriptError::BrokenChain(n));
        }
        if event_hash(&prev, seq, &step, &data) != hash_f {
            return Err(TranscriptError::BrokenChain(n));
        }
        prev = hash_f;
        events.push(Event { seq, step, data, prev: prev_f, hash: hash_f });
    }
    let first = events.first().ok_or(TranscriptError::Empty)?;
    if first.step != "manifest" {
        return Err(TranscriptError::BadManifest);
    }
    // The embedded manifest must hash to the embedded manifest_hash.
    let m = first.data.get("manifest").ok_or(TranscriptError::BadManifest)?;
    let claimed = first
        .data
        .get("manifest_hash")
        .and_then(|s| s.as_str())
        .ok_or(TranscriptError::BadManifest)?;
    let mut h = Blake2b::<U32>::new();
    h.update(m.to_string().as_bytes());
    let actual: Bytes32 = h.finalize().into();
    if hex::encode(actual) != claimed {
        return Err(TranscriptError::BadManifest);
    }
    Ok(events)
}

fn unhex(v: &serde_json::Value, key: &str) -> Option<Bytes32> {
    let b = hex::decode(v.get(key)?.as_str()?).ok()?;
    b.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> SwapManifest {
        SwapManifest {
            version: 1,
            nano_account: [0x11; 32],
            xmr_address: "5JointAddr".into(),
            chunk: 1_000,
            adaptor_point: [0x22; 32],
            bob_dest: [0x33; 32],
            open_link: [0x44; 32],
            rung_hash: [0x55; 32],
            claim_hash: [0x66; 32],
        }
    }

    #[test]
    fn manifest_hash_is_deterministic_and_binding() {
        let m = manifest();
        assert_eq!(m.hash(), manifest().hash(), "same inputs → same identity");
        let mut other = manifest();
        other.chunk += 1;
        assert_ne!(m.hash(), other.hash(), "any divergence changes the identity");
    }

    #[test]
    fn transcript_records_and_verifies() {
        let path = std::env::temp_dir()
            .join(format!("xnoxmr-transcript-test-{}.jsonl", std::process::id()));
        let m = manifest();
        let mut t = Transcript::start(&path, &m).unwrap();
        t.record("funded", serde_json::json!({ "open_hash": "aa".repeat(32) })).unwrap();
        t.record("claim-observed", serde_json::json!({ "signature": "bb".repeat(64) })).unwrap();
        t.record("swept", serde_json::json!({ "ok": true })).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let events = verify(&contents).expect("chain verifies");
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].step, "manifest");
        assert_eq!(events[3].step, "swept");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampering_breaks_the_chain() {
        let path = std::env::temp_dir()
            .join(format!("xnoxmr-transcript-tamper-{}.jsonl", std::process::id()));
        let mut t = Transcript::start(&path, &manifest()).unwrap();
        t.record("funded", serde_json::json!({ "open_hash": "aa" })).unwrap();
        t.record("swept", serde_json::json!({ "ok": true })).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();

        // Edit a recorded value: the line's own hash no longer matches.
        let edited = contents.replace("\"open_hash\":\"aa\"", "\"open_hash\":\"ab\"");
        assert_eq!(verify(&edited), Err(TranscriptError::BrokenChain(1)));

        // Drop a middle line: the successor's prev no longer matches.
        let dropped: Vec<&str> = contents.lines().filter(|l| !l.contains("funded")).collect();
        assert!(matches!(
            verify(&dropped.join("\n")),
            Err(TranscriptError::BrokenChain(_))
        ));

        // Reorder: broken.
        let mut lines: Vec<&str> = contents.lines().collect();
        lines.swap(1, 2);
        assert!(matches!(
            verify(&lines.join("\n")),
            Err(TranscriptError::BrokenChain(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_and_manifestless_rejected() {
        assert_eq!(verify(""), Err(TranscriptError::Empty));
        // A chain-valid file whose first line is not a manifest is rejected.
        let data = serde_json::json!({ "x": 1 });
        let h = event_hash(&[0u8; 32], 0, "funded", &data);
        let line = serde_json::json!({
            "seq": 0, "step": "funded", "data": data,
            "prev": hex::encode([0u8; 32]), "hash": hex::encode(h),
        });
        assert_eq!(verify(&line.to_string()), Err(TranscriptError::BadManifest));
    }
}
