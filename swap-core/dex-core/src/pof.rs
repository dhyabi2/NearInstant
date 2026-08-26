//! Proof-of-funds (PoF) — issue I7's `pof_hash` hook, made real for the Nano
//! leg and structured (not re-implemented) for the Monero leg.
//!
//! An order carries a `pof_hash`: the Blake2b hash of a proof that the maker
//! controls at least `amount`. The `pof_hash` field is asset-agnostic — it is
//! the hash of whichever proof applies, so the book verifies one field either
//! way.
//!
//! - [`NanoFundsProof`]: a signed statement (ed25519-blake2b, the same signing
//!   stack as orders and blocks) binding the maker's account, amount, expiry,
//!   and order hash. Offline-verifiable (signature + expiry + binding); the
//!   authoritative *balance* check is a node `account_info` query, performed by
//!   the gossip edge and folded into the book's `pof_verified` flag (B1).
//! - [`MoneroReserveProof`]: wraps a wallet-generated Monero reserve proof
//!   (`monero-wallet-rpc get_reserve_proof` with `message = order_hash`). The
//!   cryptographic check is `check_reserve_proof` against a node — not
//!   re-implemented here; this type just binds and hashes the proof so it can
//!   ride the same `pof_hash` field.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use crate::order::Bytes32;

/// Exact wire length of a [`NanoFundsProof`]: magic (19) + account (32) +
/// amount (16) + as_of_block (8) + expires (8) + nonce (8) + signature (64).
pub const NANO_POF_WIRE_LEN: usize = 19 + 32 + 16 + 8 + 8 + 8 + 64;

/// The outcome of checking a proof against a live account balance.
///
/// `verify` alone only proves *key ownership* (the maker's signature over a
/// claim). `FundsStatus` is what `verify` is not: an assessment of whether the
/// maker **actually holds** the claimed amount *now*, sourced from an
/// authoritative balance (a Nano node or a quorum of them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundsStatus {
    /// The live balance covers the claimed amount.
    Funded { balance: u128 },
    /// The live balance is below the claimed amount.
    Insufficient { balance: u128 },
    /// The proof's expiry has passed (it was once valid, now dead).
    Stale,
    /// No authoritative balance could be obtained, or the proof is
    /// structurally/signature invalid — nothing can be concluded.
    Unverifiable,
}

impl FundsStatus {
    /// True only for a quorum-backed, live balance that covers the claim.
    pub fn is_funded(&self) -> bool {
        matches!(self, FundsStatus::Funded { .. })
    }
}

/// A maker's signed Nano proof-of-funds for one order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NanoFundsProof {
    /// The maker's Nano account public key (also the signing key).
    pub account: Bytes32,
    /// Claimed spendable balance, in raw (≥ the order's sell amount).
    pub amount: u128,
    /// The block height the balance was observed at (0 = "latest").
    pub as_of_block: u64,
    /// Unix seconds after which the proof is dead.
    pub expires: u64,
    /// The order's anti-replay nonce — binds this proof to exactly one order
    /// (NOT the order hash: the order's `pof_hash` points at this proof, so
    /// binding the proof to the order hash would be circular).
    pub nonce: u64,
    /// ed25519-blake2b signature over [`NanoFundsProof::message`].
    pub signature: [u8; 64],
}

impl NanoFundsProof {
    /// The canonical byte string that is hashed and signed.
    pub fn message(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(16 + 32 + 16 + 8 + 8 + 8);
        m.extend_from_slice(b"XNOXMR-NANO-POF-v1\0");
        m.extend_from_slice(&self.account);
        m.extend_from_slice(&self.amount.to_be_bytes());
        m.extend_from_slice(&self.as_of_block.to_be_bytes());
        m.extend_from_slice(&self.expires.to_be_bytes());
        m.extend_from_slice(&self.nonce.to_be_bytes());
        m
    }

    /// The hash an order's `pof_hash` field must equal for this proof to apply.
    pub fn hash(&self) -> Bytes32 {
        let mut h = Blake2b::<U32>::new();
        h.update(self.message());
        h.finalize().into()
    }

    /// Sign a proof with the maker's account key. `nonce` must equal the order's
    /// `nonce` so the proof binds to exactly that order.
    pub fn sign(
        account: Bytes32,
        amount: u128,
        as_of_block: u64,
        expires: u64,
        nonce: u64,
        key: &signing::SigningKey,
    ) -> Self {
        let proof = Self {
            account,
            amount,
            as_of_block,
            expires,
            nonce,
            signature: [0u8; 64],
        };
        let sig = key.sign(rand_core::OsRng, &proof.message());
        let signature = sig.serialize().expect("64-byte signature").try_into().expect("64 bytes");
        Self { signature, ..proof }
    }

    /// Verify the signature, expiry, and that the signer is the claimed
    /// account. Balance authorization is a separate node query.
    pub fn verify(&self, now: u64) -> bool {
        self.amount > 0
            && self.expires > now
            && signing::nano_verify::verify(&self.account, &self.message(), &self.signature)
    }

    /// Assess this proof against a **live** account balance (already fetched
    /// from a node or quorum by the caller). Signature is checked first — a
    /// bad signature means the claim is untrustworthy regardless of balance —
    /// then expiry, then the balance against the claimed `amount`.
    ///
    /// This is the authoritative "does the maker actually hold the funds"
    /// gate. A `None` balance means the caller had no authoritative source,
    /// which must be treated as unverifiable, never as funded.
    pub fn assess(&self, now: u64, balance: Option<u128>) -> FundsStatus {
        if self.amount == 0
            || !signing::nano_verify::verify(&self.account, &self.message(), &self.signature)
        {
            return FundsStatus::Unverifiable;
        }
        if self.expires <= now {
            return FundsStatus::Stale;
        }
        match balance {
            None => FundsStatus::Unverifiable,
            Some(b) if b >= self.amount => FundsStatus::Funded { balance: b },
            Some(b) => FundsStatus::Insufficient { balance: b },
        }
    }

    /// Whether this proof funds `order`: same maker, same nonce, and its hash
    /// equals the order's `pof_hash` field. All three must hold or the proof is
    /// unrelated to (or replayed across) the order.
    pub fn matches_order(&self, order: &crate::order::SignedOrder) -> bool {
        self.account == order.body.maker
            && self.nonce == order.body.nonce
            && self.hash() == order.body.pof_hash
    }

    /// Wire form: the canonical message followed by the 64-byte signature.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut w = self.message();
        w.extend_from_slice(&self.signature);
        w
    }

    /// Decode a wire proof. Verifies structure only; call [`Self::verify`] for
    /// signature/expiry checks.
    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        const MAGIC: &[u8] = b"XNOXMR-NANO-POF-v1\0";
        const BODY: usize = 32 + 16 + 8 + 8 + 8;
        if bytes.len() != NANO_POF_WIRE_LEN {
            return None;
        }
        if bytes.len() != MAGIC.len() + BODY + 64 {
            return None;
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return None;
        }
        let b = &bytes[MAGIC.len()..];
        let account: Bytes32 = b[0..32].try_into().ok()?;
        let amount = u128::from_be_bytes(b[32..48].try_into().ok()?);
        let as_of_block = u64::from_be_bytes(b[48..56].try_into().ok()?);
        let expires = u64::from_be_bytes(b[56..64].try_into().ok()?);
        let nonce = u64::from_be_bytes(b[64..72].try_into().ok()?);
        let signature: [u8; 64] = b[72..136].try_into().ok()?;
        let p = Self {
            account,
            amount,
            as_of_block,
            expires,
            nonce,
            signature,
        };
        // Round-trip guard.
        if p.message() != bytes[..MAGIC.len() + BODY] {
            return None;
        }
        Some(p)
    }
}

/// A maker's Monero reserve proof for one order — a wrapper around the
/// wallet-generated proof (`monero-wallet-rpc get_reserve_proof`, with
/// `message = order_hash`), bound and hashed so it rides the same `pof_hash`
/// field as [`NanoFundsProof`]. The cryptographic check is `check_reserve_proof`
/// against a node; this type only binds the fields so the book can verify the
/// hash and the amount/order linkage offline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoneroReserveProof {
    /// The maker's primary Monero address the proof was generated for.
    pub address: String,
    /// The claimed reserved amount (in atomic piconero).
    pub amount: u128,
    /// The order hash this proof funds (also the reserve-proof `message`).
    pub order_hash: Bytes32,
    /// The wallet's reserve-proof signature (opaque, verified by the node).
    pub proof: String,
}

impl MoneroReserveProof {
    /// The canonical byte string hashed into the order's `pof_hash`.
    pub fn message(&self) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"XNOXMR-XMR-POF-v1\0");
        m.extend_from_slice(self.address.as_bytes());
        m.extend_from_slice(&self.amount.to_be_bytes());
        m.extend_from_slice(&self.order_hash);
        m.extend_from_slice(self.proof.as_bytes());
        m
    }

    /// The hash an order's `pof_hash` field must equal for this proof to apply.
    pub fn hash(&self) -> Bytes32 {
        let mut h = Blake2b::<U32>::new();
        h.update(self.message());
        h.finalize().into()
    }

    /// Offline structural/binding checks: non-zero amount, non-empty proof, and
    /// the hash matches the order's `pof_hash`. The authoritative check is
    /// `check_reserve_proof` on a node (not performed here).
    pub fn matches_order(&self, order: &crate::order::SignedOrder) -> bool {
        self.amount > 0
            && !self.proof.is_empty()
            && self.order_hash == order.body.hash()
            && self.hash() == order.body.pof_hash
    }

    /// Wire form: `magic ‖ amount ‖ order_hash ‖ u32 address_len ‖ address ‖
    /// u32 proof_len ‖ proof`. Length-prefixed (the address and the opaque
    /// proof string are variable-length), so it rides the same "order bytes
    /// followed by proof bytes" frame as [`NanoFundsProof`].
    pub fn to_wire(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(18 + 16 + 32 + 4 + self.address.len() + 4 + self.proof.len());
        w.extend_from_slice(b"XNOXMR-XMR-POF-v1\0");
        w.extend_from_slice(&self.amount.to_be_bytes());
        w.extend_from_slice(&self.order_hash);
        w.extend_from_slice(&(self.address.len() as u32).to_be_bytes());
        w.extend_from_slice(self.address.as_bytes());
        w.extend_from_slice(&(self.proof.len() as u32).to_be_bytes());
        w.extend_from_slice(self.proof.as_bytes());
        w
    }

    /// Decode a wire proof. Structural only; call [`Self::matches_order`] for
    /// the offline binding check and `check_reserve_proof` (a wallet-rpc node)
    /// for the authoritative solvency check.
    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        const MAGIC: &[u8] = b"XNOXMR-XMR-POF-v1\0";
        let b = bytes.strip_prefix(MAGIC)?;
        if b.len() < 16 + 32 + 4 + 4 {
            return None;
        }
        let amount = u128::from_be_bytes(b[0..16].try_into().ok()?);
        let order_hash: Bytes32 = b[16..48].try_into().ok()?;
        let addr_len = u32::from_be_bytes(b[48..52].try_into().ok()?) as usize;
        let addr_start = 52;
        let address = std::str::from_utf8(b.get(addr_start..addr_start + addr_len)?)
            .ok()?
            .to_string();
        let plen_start = addr_start + addr_len;
        let proof_len = u32::from_be_bytes(b.get(plen_start..plen_start + 4)?.try_into().ok()?)
            as usize;
        let pstart = plen_start + 4;
        let proof = std::str::from_utf8(b.get(pstart..pstart + proof_len)?)
            .ok()?
            .to_string();
        if b.len() != pstart + proof_len {
            return None;
        }
        let p = Self {
            address,
            amount,
            order_hash,
            proof,
        };
        // Round-trip guard: the decoded fields must re-serialize exactly.
        if p.to_wire() != bytes {
            return None;
        }
        Some(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn proof_signs_verifies_and_binds_to_one_order() {
        let key = signing::SigningKey::new(&mut OsRng);
        let account: Bytes32 = signing::VerifyingKey::from(&key)
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let nonce = 7u64;
        let p = NanoFundsProof::sign(account, 1_000_000, 123, 100_000, nonce, &key);
        assert!(p.verify(100));
        // Expired → dead.
        assert!(!p.verify(100_000));
        // A different nonce → different hash; replaying the proof on another
        // order is caught by the pof_hash + nonce mismatch at the book layer.
        let mut rebound = p.clone();
        rebound.nonce = 8;
        assert_ne!(p.hash(), rebound.hash());
        // Tampering the amount breaks the signature.
        let mut tampered = p.clone();
        tampered.amount += 1;
        assert!(!tampered.verify(100));
        // A different key cannot sign for the claimed account.
        let other = signing::SigningKey::new(&mut OsRng);
        let forged = NanoFundsProof::sign(account, 1_000_000, 123, 100_000, nonce, &other);
        assert!(!forged.verify(100));
    }

    #[test]
    fn proof_matches_exactly_the_order_it_funds() {
        let key = signing::SigningKey::new(&mut OsRng);
        let account: Bytes32 = signing::VerifyingKey::from(&key)
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();

        let mk_order = |nonce: u64, pof_hash: Bytes32| {
            use crate::order::{OrderBody, SignedOrder, Side};
            let body = OrderBody {
                maker: account,
                side: Side::SellXno,
                amount: 1_000,
                rate_pico: 3_750_000_000,
                expiry: 100_000,
                nonce,
                pof_hash,
            };
            let sig = key.sign(OsRng, &body.encode());
            SignedOrder {
                body,
                signature: sig.serialize().unwrap().try_into().unwrap(),
            }
        };

        // The proof binds to the order by NONCE (the order's pof_hash points at
        // the proof; no circularity).
        let proof = NanoFundsProof::sign(account, 5_000, 0, 100_000, 2, &key);
        let funded = mk_order(2, proof.hash());
        assert!(proof.matches_order(&funded));
        // Same maker + same pof_hash but a different nonce → unrelated.
        let other_nonce = mk_order(3, proof.hash());
        assert!(!proof.matches_order(&other_nonce), "proof must not fund a different order");

        // Wire round-trip.
        let back = NanoFundsProof::from_wire(&proof.to_wire()).expect("round trips");
        assert_eq!(back, proof);
        assert!(back.verify(100));
    }

    #[test]
    fn assess_turns_balance_into_funded_insufficient_or_stale() {
        let key = signing::SigningKey::new(&mut OsRng);
        let account: Bytes32 = signing::VerifyingKey::from(&key)
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        // Claims 1,000,000 raw, expires at 100_000, nonce 7.
        let p = NanoFundsProof::sign(account, 1_000_000, 0, 100_000, 7, &key);

        // Live balance covers the claim → funded.
        assert_eq!(
            p.assess(100, Some(5_000_000)),
            FundsStatus::Funded { balance: 5_000_000 }
        );
        assert!(p.assess(100, Some(5_000_000)).is_funded());
        // Balance below the claim → insufficient (not funded).
        assert_eq!(
            p.assess(100, Some(999_999)),
            FundsStatus::Insufficient { balance: 999_999 }
        );
        assert!(!p.assess(100, Some(999_999)).is_funded());
        // Expired → stale even with a healthy balance.
        assert_eq!(p.assess(100_000, Some(5_000_000)), FundsStatus::Stale);
        // No authoritative balance → unverifiable, never funded.
        assert_eq!(p.assess(100, None), FundsStatus::Unverifiable);
        // A tampered amount breaks the signature → unverifiable.
        let mut tampered = p.clone();
        tampered.amount += 1;
        assert_eq!(tampered.assess(100, Some(5_000_000)), FundsStatus::Unverifiable);
    }

    #[test]
    fn monero_reserve_proof_round_trips_the_wire() {
        let rp = MoneroReserveProof {
            address: "45Yq8kWicK2jQXGhPJjWUg6ysP6CKgq6yk8rQ7m6m9WmNfBW6yd1KrFBw1bJ1TQF5pCqW7VXs9NTF7NwB1BtC8fJQfB1rM9".to_string(),
            amount: 5_000_000_000_000,
            order_hash: [0xAB; 32],
            proof: "ReserveProofV1deadbeefcafebabe...".to_string(),
        };
        let wire = rp.to_wire();
        let back = MoneroReserveProof::from_wire(&wire).expect("round trips");
        assert_eq!(back, rp);
        // Truncated / garbled wire is rejected, not mis-decoded.
        assert!(MoneroReserveProof::from_wire(&wire[..wire.len() - 1]).is_none());
        assert!(MoneroReserveProof::from_wire(b"garbage").is_none());
    }
}
