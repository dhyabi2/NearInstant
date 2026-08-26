//! Crash-safe settlement checkpoints — an interrupted swap resumes to a safe
//! terminal state without the counterparty (R-series, recovery brainstorm).
//!
//! The insight: after the wire ceremony completes (DKG, contributions, guard
//! rung, adaptor pre-sign), NEITHER side needs the other online again. Bob
//! settles against the Nano nodes alone; Alice extracts the revealed secret
//! from the on-chain claim — which the ledger stores forever — and sweeps.
//! So one small file persisted at that boundary makes the whole tail of the
//! swap replayable after a crash, reboot, or power cut:
//!
//! - [`AliceCheckpoint`] (written right after the pre-sign, before waiting):
//!   the joint Monero material, the pre-signature, and the claim hash. Resume
//!   = poll for the claim, extract `x`, reconstruct, sweep. No deadline: the
//!   claim signature is permanent on-chain and the joint output never expires.
//! - [`BobCheckpoint`] (written right after the XMR lock matures and the
//!   ceremony completes, before settling): the signed rung, the claim, the
//!   pre-signature and its work. Resume = the normal confirm-then-reveal
//!   settle; if the claim is already on-chain (crash AFTER settling), resume
//!   recognises it and finishes as a no-op success.
//!
//! Checkpoints hold NO secrets: spend secrets stay in the operator's config.
//! A stolen checkpoint file reveals session metadata, never funds. Files are
//! written atomically (temp + rename) and deleted on a clean finish.

use std::path::Path;

use nano_ceremony::block::{SignedBlock, StateBlock, Subtype};
use nano_ceremony::broadcast::NanoNode;
use nano_ceremony::Bytes32;
use signing::adaptor::PreSignature;

use crate::driver::{alice_settle_chunk, bob_settle_chunk, XmrSide};
use crate::monero::JointXmr;
use crate::session::{wait_for_claim, SessionError};

/// Alice's post-ceremony state: everything needed to finish her side alone.
#[derive(Clone, Debug, PartialEq)]
pub struct AliceCheckpoint {
    pub joint: JointXmr,
    pub presig: PreSignature,
    pub claim_hash: Bytes32,
    pub chunk: u128,
}

/// Bob's post-lock state: everything needed to settle his side alone.
#[derive(Clone, Debug, PartialEq)]
pub struct BobCheckpoint {
    pub joint: JointXmr,
    pub rung: SignedBlock,
    pub claim: StateBlock,
    pub claim_work: u64,
    pub presig: PreSignature,
    pub chunk: u128,
}

/// Errors reading/writing checkpoints.
#[derive(Debug)]
pub enum CheckpointError {
    Io(std::io::Error),
    /// The file is not a checkpoint, is for the other role, or is corrupt.
    Malformed(&'static str),
}

impl From<std::io::Error> for CheckpointError {
    fn from(e: std::io::Error) -> Self {
        CheckpointError::Io(e)
    }
}

// ---- JSON codec (hand-rolled: the underlying types are foreign) -----------

fn hex32(b: &Bytes32) -> String {
    hex::encode(b)
}

fn unhex32(v: &serde_json::Value, key: &'static str) -> Result<Bytes32, CheckpointError> {
    let s = v.get(key).and_then(|s| s.as_str()).ok_or(CheckpointError::Malformed(key))?;
    let bytes = hex::decode(s).map_err(|_| CheckpointError::Malformed(key))?;
    bytes.try_into().map_err(|_| CheckpointError::Malformed(key))
}

fn unhex64(v: &serde_json::Value, key: &'static str) -> Result<[u8; 64], CheckpointError> {
    let s = v.get(key).and_then(|s| s.as_str()).ok_or(CheckpointError::Malformed(key))?;
    let bytes = hex::decode(s).map_err(|_| CheckpointError::Malformed(key))?;
    bytes.try_into().map_err(|_| CheckpointError::Malformed(key))
}

fn u128_of(v: &serde_json::Value, key: &'static str) -> Result<u128, CheckpointError> {
    v.get(key)
        .and_then(|s| s.as_str())
        .and_then(|s| s.parse().ok())
        .ok_or(CheckpointError::Malformed(key))
}

fn joint_json(j: &JointXmr) -> serde_json::Value {
    serde_json::json!({
        "context": hex32(&j.context),
        "spend_pubs": j.spend_pubs.iter().map(hex32).collect::<Vec<_>>(),
        "spend_pub": hex32(&j.spend_pub),
        "view_key": hex32(&j.view_key),
        "address": j.address,
    })
}

fn joint_of(v: &serde_json::Value) -> Result<JointXmr, CheckpointError> {
    let j = v.get("joint").ok_or(CheckpointError::Malformed("joint"))?;
    let pubs = j
        .get("spend_pubs")
        .and_then(|a| a.as_array())
        .ok_or(CheckpointError::Malformed("spend_pubs"))?;
    let mut spend_pubs = Vec::with_capacity(pubs.len());
    for p in pubs {
        let s = p.as_str().ok_or(CheckpointError::Malformed("spend_pubs"))?;
        let b = hex::decode(s).map_err(|_| CheckpointError::Malformed("spend_pubs"))?;
        spend_pubs.push(b.try_into().map_err(|_| CheckpointError::Malformed("spend_pubs"))?);
    }
    Ok(JointXmr {
        context: unhex32(j, "context")?,
        spend_pubs,
        spend_pub: unhex32(j, "spend_pub")?,
        view_key: unhex32(j, "view_key")?,
        address: j
            .get("address")
            .and_then(|s| s.as_str())
            .ok_or(CheckpointError::Malformed("address"))?
            .to_string(),
    })
}

fn presig_json(p: &PreSignature) -> serde_json::Value {
    serde_json::json!({
        "r_adapted": hex::encode(p.r_adapted),
        "s_hat": hex::encode(p.s_hat),
        "adaptor_point": hex::encode(p.adaptor_point),
    })
}

fn presig_of(v: &serde_json::Value) -> Result<PreSignature, CheckpointError> {
    let p = v.get("presig").ok_or(CheckpointError::Malformed("presig"))?;
    Ok(PreSignature {
        r_adapted: unhex32(p, "r_adapted")?,
        s_hat: unhex32(p, "s_hat")?,
        adaptor_point: unhex32(p, "adaptor_point")?,
    })
}

fn subtype_str(s: Subtype) -> &'static str {
    match s {
        Subtype::Open => "open",
        Subtype::Receive => "receive",
        Subtype::Send => "send",
        Subtype::Change => "change",
    }
}

fn subtype_of(s: &str) -> Result<Subtype, CheckpointError> {
    Ok(match s {
        "open" => Subtype::Open,
        "receive" => Subtype::Receive,
        "send" => Subtype::Send,
        "change" => Subtype::Change,
        _ => return Err(CheckpointError::Malformed("subtype")),
    })
}

fn block_json(b: &StateBlock) -> serde_json::Value {
    serde_json::json!({
        "account": hex32(&b.account),
        "previous": hex32(&b.previous),
        "representative": hex32(&b.representative),
        "balance": b.balance.to_string(),
        "link": hex32(&b.link),
        "subtype": subtype_str(b.subtype),
    })
}

fn block_of(v: &serde_json::Value, key: &'static str) -> Result<StateBlock, CheckpointError> {
    let b = v.get(key).ok_or(CheckpointError::Malformed(key))?;
    Ok(StateBlock {
        account: unhex32(b, "account")?,
        previous: unhex32(b, "previous")?,
        representative: unhex32(b, "representative")?,
        balance: u128_of(b, "balance")?,
        link: unhex32(b, "link")?,
        subtype: subtype_of(
            b.get("subtype")
                .and_then(|s| s.as_str())
                .ok_or(CheckpointError::Malformed("subtype"))?,
        )?,
    })
}

impl AliceCheckpoint {
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "v": 1,
            "role": "alice",
            "joint": joint_json(&self.joint),
            "presig": presig_json(&self.presig),
            "claim_hash": hex32(&self.claim_hash),
            "chunk": self.chunk.to_string(),
        })
        .to_string()
    }

    pub fn from_json(s: &str) -> Result<Self, CheckpointError> {
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|_| CheckpointError::Malformed("json"))?;
        if v.get("role").and_then(|r| r.as_str()) != Some("alice") {
            return Err(CheckpointError::Malformed("role"));
        }
        Ok(Self {
            joint: joint_of(&v)?,
            presig: presig_of(&v)?,
            claim_hash: unhex32(&v, "claim_hash")?,
            chunk: u128_of(&v, "chunk")?,
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), CheckpointError> {
        write_atomic(path, &self.to_json())
    }

    pub fn load(path: &Path) -> Result<Self, CheckpointError> {
        Self::from_json(&std::fs::read_to_string(path)?)
    }
}

impl BobCheckpoint {
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "v": 1,
            "role": "bob",
            "joint": joint_json(&self.joint),
            "rung": { "block": block_json(&self.rung.block),
                      "signature": hex::encode(self.rung.signature),
                      "work": format!("{:016x}", self.rung.work) },
            "claim": block_json(&self.claim),
            "claim_work": format!("{:016x}", self.claim_work),
            "presig": presig_json(&self.presig),
            "chunk": self.chunk.to_string(),
        })
        .to_string()
    }

    pub fn from_json(s: &str) -> Result<Self, CheckpointError> {
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|_| CheckpointError::Malformed("json"))?;
        if v.get("role").and_then(|r| r.as_str()) != Some("bob") {
            return Err(CheckpointError::Malformed("role"));
        }
        let rung_v = v.get("rung").ok_or(CheckpointError::Malformed("rung"))?;
        let rung = SignedBlock {
            block: block_of(rung_v, "block")?,
            signature: unhex64(rung_v, "signature")?,
            work: work_of(rung_v, "work")?,
        };
        Ok(Self {
            joint: joint_of(&v)?,
            rung,
            claim: block_of(&v, "claim")?,
            claim_work: work_of(&v, "claim_work")?,
            presig: presig_of(&v)?,
            chunk: u128_of(&v, "chunk")?,
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), CheckpointError> {
        write_atomic(path, &self.to_json())
    }

    pub fn load(path: &Path) -> Result<Self, CheckpointError> {
        Self::from_json(&std::fs::read_to_string(path)?)
    }
}

fn work_of(v: &serde_json::Value, key: &'static str) -> Result<u64, CheckpointError> {
    v.get(key)
        .and_then(|s| s.as_str())
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .ok_or(CheckpointError::Malformed(key))
}

/// Write via temp file + rename so a crash mid-write never leaves a truncated
/// checkpoint behind.
fn write_atomic(path: &Path, contents: &str) -> Result<(), CheckpointError> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ---- resume ---------------------------------------------------------------

/// Resume Alice from a checkpoint: poll the nodes for the (permanent) claim
/// signature, extract Bob's revealed secret, reconstruct the joint Monero
/// spend secret, sweep. Needs only her own spend secret from config — no wire,
/// no counterparty, no deadline.
pub fn resume_alice(
    nodes: &[&dyn NanoNode],
    xmr: &dyn XmrSide,
    alice_spend_secret: &Bytes32,
    cp: &AliceCheckpoint,
    progress: &mut dyn FnMut(&str),
) -> Result<Bytes32, SessionError> {
    progress("Resuming: looking for the settled claim…");
    let claim_sig = wait_for_claim(nodes, &cp.claim_hash)
        .ok_or(SessionError::Driver(crate::driver::DriverError::ClaimRejected))?;
    progress("Receiving your XMR…");
    alice_settle_chunk(xmr, &cp.joint, alice_spend_secret, &cp.presig, &claim_sig)
        .map_err(SessionError::Driver)
}

/// Resume Bob from a checkpoint. If the claim is already on-chain (the crash
/// happened AFTER the reveal) this is a no-op success; otherwise it re-runs
/// the normal confirm-rung-then-reveal settle. Needs only his spend secret
/// from config.
pub fn resume_bob(
    nodes: &[&dyn NanoNode],
    bob_spend_secret: &Bytes32,
    cp: &BobCheckpoint,
    quorum: usize,
    attempts: usize,
    progress: &mut dyn FnMut(&str),
) -> Result<(), SessionError> {
    let claim_hash = cp.claim.hash();
    if nodes.iter().any(|n| n.block(&claim_hash).is_some()) {
        progress("Resuming: claim already settled — nothing to do.");
        return Ok(());
    }
    progress("Resuming: confirming and settling…");
    bob_settle_chunk(
        nodes,
        &cp.rung,
        &cp.presig,
        bob_spend_secret,
        &cp.claim,
        cp.claim_work,
        quorum,
        attempts,
        &mut || std::thread::sleep(std::time::Duration::from_secs(1)),
    )
    .map_err(SessionError::Driver)?;
    Ok(())
}
