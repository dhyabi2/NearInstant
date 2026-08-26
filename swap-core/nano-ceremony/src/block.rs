//! Nano state blocks: construction, hashing, and RPC wire form.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use crate::Bytes32;

/// The state-block preamble: 31 zero bytes then 0x06.
const PREAMBLE: Bytes32 = {
    let mut p = [0u8; 32];
    p[31] = 6;
    p
};

/// Block subtype, determined by how the block changes account state. Nano
/// nodes infer it, but the RPC `process` call wants it stated explicitly so a
/// mismatched block is rejected instead of misapplied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subtype {
    /// First block of an account; `previous` is zero, `link` is the pending send.
    Open,
    /// Pockets a pending send; `link` is the pending send's hash.
    Receive,
    /// Decreases balance; `link` is the destination public key.
    Send,
    /// Moves nothing; only the representative (and frontier) change.
    Change,
}

impl Subtype {
    pub fn as_str(&self) -> &'static str {
        match self {
            Subtype::Open => "open",
            Subtype::Receive => "receive",
            Subtype::Send => "send",
            Subtype::Change => "change",
        }
    }
}

/// An unsigned Nano state block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateBlock {
    /// The account's public key.
    pub account: Bytes32,
    /// Hash of the previous block on this account's chain (zero for open).
    pub previous: Bytes32,
    /// Representative public key.
    pub representative: Bytes32,
    /// Balance *after* this block, in raw.
    pub balance: u128,
    /// Link field; meaning depends on the subtype.
    pub link: Bytes32,
    /// Declared subtype (wire hint; not part of the hash).
    pub subtype: Subtype,
}

impl StateBlock {
    /// The Blake2b-256 block hash — the message the joint key signs.
    pub fn hash(&self) -> Bytes32 {
        let mut h = Blake2b::<U32>::new();
        h.update(PREAMBLE);
        h.update(self.account);
        h.update(self.previous);
        h.update(self.representative);
        h.update(self.balance.to_be_bytes());
        h.update(self.link);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }

    /// The proof-of-work root: the previous hash, or the account key for the
    /// first block of an account. Known before this block is broadcast, which
    /// is what lets N4 pipeline work ahead of the chunk stream.
    pub fn work_root(&self) -> Bytes32 {
        if self.previous == [0u8; 32] {
            self.account
        } else {
            self.previous
        }
    }

    /// A change block advancing the frontier from `previous` without moving
    /// value — the guard-ladder rung shape (I3).
    pub fn change(
        account: Bytes32,
        previous: Bytes32,
        representative: Bytes32,
        balance: u128,
    ) -> Self {
        StateBlock {
            account,
            previous,
            representative,
            balance,
            link: [0u8; 32],
            subtype: Subtype::Change,
        }
    }
}

/// A signed, work-attached block ready for broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBlock {
    pub block: StateBlock,
    pub signature: [u8; 64],
    pub work: u64,
}

impl SignedBlock {
    /// Verify the signature against the block's account key (Nano semantics).
    pub fn verify_signature(&self) -> bool {
        signing::nano_verify::verify(&self.block.account, &self.block.hash(), &self.signature)
    }

    /// The RPC `process` JSON body for this block.
    #[cfg(feature = "rpc")]
    pub fn to_process_json(&self) -> serde_json::Value {
        let b = &self.block;
        serde_json::json!({
            "action": "process",
            "json_block": "true",
            "subtype": b.subtype.as_str(),
            "block": {
                "type": "state",
                "account": crate::address::encode(&b.account),
                "previous": hex::encode_upper(b.previous),
                "representative": crate::address::encode(&b.representative),
                "balance": b.balance.to_string(),
                "link": hex::encode_upper(b.link),
                "signature": hex::encode_upper(self.signature),
                "work": format!("{:016x}", self.work),
            }
        })
    }
}
