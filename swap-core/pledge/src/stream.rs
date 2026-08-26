//! The provable drip (H5 hard variant): penalty released in timed
//! installments that *nobody* — including the recipient — can accelerate,
//! and any third party can watch pace out on-chain.
//!
//! Construction:
//! - After the leaver's exit blocks settle, the penalty **stays in the joint
//!   account**. A chain of N installment sends (each `penalty/N` to the
//!   stayer) is jointly pre-signed at setup.
//! - The *leaver* aggregates those signatures and hands the stayer only
//!   **sealed** copies: signature `k` is XOR-encrypted under a key derived
//!   from `v_k`, the value hidden in link `k` of an RSW chain in which
//!   **only the first link's starting point is public** — link `k+1`'s
//!   starting point is `H(v_k)`, never published. Solving link `k` costs
//!   `t_unit` sequential squarings and is the only way to learn where link
//!   `k+1` even begins, so parallel hardware buys nothing: installment `k`
//!   unseals ≈ `k` intervals after grinding starts.
//! - The stayer cannot decrypt early (they hold ciphertexts and their own
//!   FROST share only), the leaver cannot steal (installments pay the
//!   stayer), and Nano's frontier rule forces settlement in order — the
//!   pacing is publicly visible on-chain.
//! - Sealing honesty is cut-and-choose (the Block 5 pattern): the leaver
//!   produces `m` independent bundles of the same signatures; the stayer
//!   opens half (leaver reveals those trapdoors; every ciphertext is checked
//!   to decrypt to a valid signature, and the hidden chain to link
//!   correctly, in milliseconds) and keeps the rest for use.

use blake2::digest::consts::U64;
use blake2::{Blake2b, Digest};
use num_bigint_dig::BigUint;
use rand::seq::SliceRandom;
use rand::RngCore;

use nano_ceremony::block::{StateBlock, Subtype};
use nano_ceremony::Bytes32;
use puzzle_escrow::puzzle::Trapdoor;

/// Build the drip chain: N chained sends of `penalty/N` (remainder folded
/// into the last) from the joint account to the stayer, starting at
/// `frontier` with `penalty` still on balance.
pub fn drip_chain(
    account: Bytes32,
    frontier: Bytes32,
    representative: Bytes32,
    penalty: u128,
    stayer_dest: Bytes32,
    n: usize,
) -> Vec<StateBlock> {
    assert!(n > 0 && penalty >= n as u128);
    let per = penalty / n as u128;
    let mut blocks = Vec::with_capacity(n);
    let mut prev = frontier;
    let mut balance = penalty;
    for i in 0..n {
        let amount = if i == n - 1 { balance } else { per };
        balance -= amount;
        let b = StateBlock {
            account,
            previous: prev,
            representative,
            balance,
            link: stayer_dest,
            subtype: Subtype::Send,
        };
        prev = b.hash();
        blocks.push(b);
    }
    blocks
}

fn h64(domain: &'static [u8], data: &[u8]) -> [u8; 64] {
    let mut h = Blake2b::<U64>::new();
    h.update(domain);
    h.update(data);
    h.finalize().into()
}

/// Keystream for sealing signature `k` from hidden value `v_k`.
fn keystream(v: &BigUint) -> [u8; 64] {
    h64(b"XNOXMR-drip-key-v1", &v.to_bytes_le())
}

/// Link `k+1`'s (secret) starting point from link `k`'s hidden value.
fn next_x0(v: &BigUint, n_mod: &BigUint) -> BigUint {
    let bytes = h64(b"XNOXMR-drip-x0-v1", &v.to_bytes_le());
    BigUint::from_bytes_le(&bytes[..32]) % n_mod
}

type Sealed = [u8; 64];

fn xor64(sig: &[u8; 64], ks: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = sig[i] ^ ks[i];
    }
    out
}

/// One seal-bundle (public; safe to hand to the stayer). Only the FIRST
/// link's starting point is present — later starts derive from solutions.
#[derive(Clone, Debug)]
pub struct SealBundle {
    pub n: BigUint,
    pub t_unit: u64,
    pub x0: BigUint,
    /// Link ciphertext values: `c_k = (v_k + x0_k^(2^t)) mod n`.
    pub c: Vec<BigUint>,
    /// Sealed signatures.
    pub sealed: Vec<Sealed>,
}

/// Fast path: `x^(2^t) mod n` via the trapdoor.
fn pow_tower(td: &Trapdoor, x: &BigUint, t: u64, n_mod: &BigUint) -> BigUint {
    let e = BigUint::from(2u32).modpow(&BigUint::from(t), &td.phi());
    x.modpow(&e, n_mod)
}

/// Slow path: `t` sequential squarings.
fn grind(x: &BigUint, t: u64, n_mod: &BigUint) -> BigUint {
    let mut y = x.clone();
    for _ in 0..t {
        y = (&y * &y) % n_mod;
    }
    y
}

/// Generate one bundle over `signatures` (leaver side; fast via trapdoor).
pub fn seal_bundle<R: RngCore + rand::CryptoRng>(
    rng: &mut R,
    signatures: &[[u8; 64]],
    trapdoor: &Trapdoor,
    t_unit: u64,
) -> SealBundle {
    let n_mod = &trapdoor.p * &trapdoor.q;
    let mut first_x0 = None;
    let mut x0 = loop {
        let x = num_bigint_dig::RandBigInt::gen_biguint_below(rng, &n_mod);
        if x > BigUint::from(1u8) {
            break x;
        }
    };
    let mut c = Vec::with_capacity(signatures.len());
    let mut sealed = Vec::with_capacity(signatures.len());
    for sig in signatures {
        if first_x0.is_none() {
            first_x0 = Some(x0.clone());
        }
        let mut vb = [0u8; 32];
        rng.fill_bytes(&mut vb);
        let v = BigUint::from_bytes_le(&vb) % &n_mod;
        let y = pow_tower(trapdoor, &x0, t_unit, &n_mod);
        c.push((&v + y) % &n_mod);
        sealed.push(xor64(sig, &keystream(&v)));
        x0 = next_x0(&v, &n_mod);
    }
    SealBundle {
        n: n_mod,
        t_unit,
        x0: first_x0.expect("at least one signature"),
        c,
        sealed,
    }
}

/// Cut-and-choose: `m` independent bundles of the same signature set.
/// Returns (public bundles, per-bundle trapdoors kept by the leaver).
pub fn make_bundles<R: RngCore + rand::CryptoRng>(
    rng: &mut R,
    signatures: &[[u8; 64]],
    m: usize,
    prime_bits: usize,
    t_unit: u64,
) -> (Vec<SealBundle>, Vec<Trapdoor>) {
    let mut pubs = Vec::with_capacity(m);
    let mut tds = Vec::with_capacity(m);
    for _ in 0..m {
        let td = puzzle_escrow::puzzle::generate_modulus(rng, prime_bits);
        pubs.push(seal_bundle(rng, signatures, &td, t_unit));
        tds.push(td);
    }
    (pubs, tds)
}

/// The stayer's random audit subset: half the bundles.
pub fn choose_audit(rng: &mut impl RngCore, m: usize) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..m).collect();
    idx.shuffle(rng);
    let mut a = idx[..m / 2].to_vec();
    a.sort_unstable();
    a
}

#[derive(Debug, PartialEq, Eq)]
pub enum StreamError {
    Malformed,
    /// An audited bundle failed: wrong modulus, broken chain, or a
    /// ciphertext that does not decrypt to a valid signature.
    AuditFailed(usize),
    /// A solved link's signature failed verification (kept-bundle tamper —
    /// caught at use, never broadcast).
    BadSignature,
}

/// Verify an audit: for each opened bundle the leaver reveals its trapdoor;
/// the stayer walks the whole chain fast, checking that every ciphertext
/// decrypts to a valid signature over its drip block. Returns kept indices.
pub fn verify_audit(
    account: &Bytes32,
    drip_blocks: &[StateBlock],
    bundles: &[SealBundle],
    audit: &[usize],
    trapdoors: &[Trapdoor],
) -> Result<Vec<usize>, StreamError> {
    if trapdoors.len() != audit.len() {
        return Err(StreamError::Malformed);
    }
    for (td, &bi) in trapdoors.iter().zip(audit) {
        let b = bundles.get(bi).ok_or(StreamError::Malformed)?;
        // Audit #15: the revealed factors must genuinely factor n, be
        // distinct, and be prime — else phi is wrong and the fast-path check
        // is unsound (matching escrow_verify's standard).
        if &td.p * &td.q != b.n
            || td.p == td.q
            || !num_bigint_dig::prime::probably_prime(&td.p, 32)
            || !num_bigint_dig::prime::probably_prime(&td.q, 32)
            || b.c.len() != drip_blocks.len()
            || b.sealed.len() != drip_blocks.len()
        {
            return Err(StreamError::AuditFailed(bi));
        }
        let mut x0 = b.x0.clone();
        for k in 0..b.c.len() {
            let y = pow_tower(td, &x0, b.t_unit, &b.n);
            let v = ((&b.c[k] + &b.n) - y) % &b.n;
            let sig = xor64(&b.sealed[k], &keystream(&v));
            if !signing::nano_verify::verify(account, &drip_blocks[k].hash(), &sig) {
                return Err(StreamError::AuditFailed(bi));
            }
            x0 = next_x0(&v, &b.n);
        }
    }
    Ok((0..bundles.len()).filter(|i| !audit.contains(i)).collect())
}

/// The stayer's solver over one kept bundle: grinds links strictly in order
/// (each link's start is unknowable before the previous solution); each
/// solved link unseals one broadcastable installment.
pub struct DripSolver<'a> {
    bundle: &'a SealBundle,
    x0: BigUint,
    next: usize,
}

impl<'a> DripSolver<'a> {
    pub fn new(bundle: &'a SealBundle) -> Self {
        Self {
            x0: bundle.x0.clone(),
            bundle,
            next: 0,
        }
    }

    /// Installments already unsealed.
    pub fn unlocked(&self) -> usize {
        self.next
    }

    /// Grind the next link (`t_unit` sequential squarings) and return the
    /// unsealed signature for drip block `unlocked()`, verified against the
    /// block before it is ever returned.
    pub fn solve_next(
        &mut self,
        account: &Bytes32,
        drip_blocks: &[StateBlock],
    ) -> Result<[u8; 64], StreamError> {
        let k = self.next;
        let b = self.bundle;
        if k >= b.c.len() {
            return Err(StreamError::Malformed);
        }
        let y = grind(&self.x0, b.t_unit, &b.n);
        let v = ((&b.c[k] + &b.n) - y) % &b.n;
        let sig = xor64(&b.sealed[k], &keystream(&v));
        let block = drip_blocks.get(k).ok_or(StreamError::Malformed)?;
        if !signing::nano_verify::verify(account, &block.hash(), &sig) {
            return Err(StreamError::BadSignature);
        }
        self.x0 = next_x0(&v, &b.n);
        self.next += 1;
        Ok(sig)
    }
}
