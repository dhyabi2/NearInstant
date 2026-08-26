//! Cut-and-choose verifiable escrow of an ed25519 scalar share.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, edwards::EdwardsPoint,
    scalar::Scalar,
};
use num_bigint_dig::BigUint;
use rand::seq::SliceRandom;
use rand::RngCore;

use crate::puzzle::{self, Puzzle, Trapdoor};

/// The ed25519 group order ℓ as a big integer.
pub fn curve_order() -> BigUint {
    // ℓ = 2^252 + 27742317777372353535851937790883648493
    (BigUint::from(1u32) << 252usize)
        + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10).unwrap()
}

pub fn scalar_to_biguint(s: &Scalar) -> BigUint {
    BigUint::from_bytes_le(&s.to_bytes())
}

fn biguint_to_scalar(v: &BigUint) -> Option<Scalar> {
    if v >= &curve_order() {
        return None;
    }
    let bytes = v.to_bytes_le();
    let mut arr = [0u8; 32];
    arr[..bytes.len()].copy_from_slice(&bytes);
    Option::from(Scalar::from_canonical_bytes(arr))
}

/// One public escrow instance.
#[derive(Clone, Debug)]
pub struct Instance {
    /// `R_i = r_i·G` (compressed).
    pub r_point: [u8; 32],
    /// `d_i = r_i + k mod ℓ`.
    pub d: [u8; 32],
    /// The puzzle hiding `r_i`.
    pub puzzle: Puzzle,
}

/// The public escrow: everything the counterparty holds.
#[derive(Clone, Debug)]
pub struct EscrowPublic {
    /// `K = k·G`, the public key of the escrowed share (compressed).
    pub share_pub: [u8; 32],
    pub instances: Vec<Instance>,
}

/// The escrower's private material.
pub struct EscrowSecret {
    pub r_values: Vec<Scalar>,
    pub trapdoors: Vec<Trapdoor>,
}

/// What the escrower reveals for each audited instance.
#[derive(Clone, Debug)]
pub struct Opening {
    pub index: usize,
    pub r: [u8; 32],
    pub p: BigUint,
    pub q: BigUint,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EscrowError {
    /// A modulus does not exceed the curve order (the S10 invariant).
    ModulusTooSmall,
    /// An audited instance failed its check.
    AuditFailed(usize),
    /// A kept instance failed the algebraic binding `d·G == R + K`.
    BindingFailed(usize),
    /// Malformed data (bad point/scalar encoding, bad index).
    Malformed,
    /// The solved share does not open `K`.
    ShareMismatch,
    /// A puzzle has no time-lock (`t == 0`) — degenerate and, before the
    /// `solve` fix, unrecoverable. Rejected outright.
    TimeLockTooShort(usize),
}

/// Create an escrow of `share` with `m` instances, each with its own fresh
/// modulus of `2·prime_bits` bits and `t` sequential squarings.
pub fn escrow_make(
    rng: &mut (impl RngCore + rand::CryptoRng),
    share: &Scalar,
    m: usize,
    prime_bits: usize,
    t: u64,
) -> (EscrowPublic, EscrowSecret) {
    let order = curve_order();
    let share_pub = (share * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let mut instances = Vec::with_capacity(m);
    let mut r_values = Vec::with_capacity(m);
    let mut trapdoors = Vec::with_capacity(m);
    for _ in 0..m {
        let r = Scalar::random(rng);
        let trapdoor = puzzle::generate_modulus(rng, prime_bits);
        // The S10 invariant, asserted at creation: N must exceed ℓ or the
        // hidden scalar truncates into garbage.
        assert!(
            &trapdoor.p * &trapdoor.q > order,
            "modulus must exceed the curve order (use prime_bits >= 128)"
        );
        let pz = puzzle::make(rng, &trapdoor, t, &scalar_to_biguint(&r));
        instances.push(Instance {
            r_point: (&r * ED25519_BASEPOINT_TABLE).compress().to_bytes(),
            d: (r + share).to_bytes(),
            puzzle: pz,
        });
        r_values.push(r);
        trapdoors.push(trapdoor);
    }
    (
        EscrowPublic {
            share_pub,
            instances,
        },
        EscrowSecret {
            r_values,
            trapdoors,
        },
    )
}

/// The verifier's random audit subset: half the instances.
pub fn choose_audit(rng: &mut impl RngCore, m: usize) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..m).collect();
    idx.shuffle(rng);
    let mut audit = idx[..m / 2].to_vec();
    audit.sort_unstable();
    audit
}

/// The escrower answers an audit by revealing `r_i` and the modulus factors
/// for each audited instance.
pub fn escrow_open(secret: &EscrowSecret, audit: &[usize]) -> Vec<Opening> {
    audit
        .iter()
        .map(|&i| Opening {
            index: i,
            r: secret.r_values[i].to_bytes(),
            p: secret.trapdoors[i].p.clone(),
            q: secret.trapdoors[i].q.clone(),
        })
        .collect()
}

fn decompress(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    CompressedEdwardsY(*bytes).decompress()
}

/// Verify the escrow: audited instances via the revealed trapdoors, kept
/// instances via the algebraic binding to `K`. On success returns the kept
/// indices — any one of them suffices for later recovery.
///
/// This wrapper enforces only the hard `t != 0` floor. A fund-gating backstop
/// should instead call [`escrow_verify_min_t`] with the N3-horizon-derived
/// minimum (see [`crate::horizon::size_t`]) so the puzzles are provably NOT
/// solvable before the swap's claim deadline.
pub fn escrow_verify(
    public: &EscrowPublic,
    audit: &[usize],
    openings: &[Opening],
) -> Result<Vec<usize>, EscrowError> {
    escrow_verify_min_t(public, audit, openings, 1)
}

/// Verify the escrow, additionally requiring every puzzle's sequential-squaring
/// count `t` to be at least `min_t`. Audit (N3 horizon): a small non-zero `t`
/// passes the `t != 0` check yet voids the time-lock — anyone solves it before
/// the counterparty's claim deadline, so the refund backstop is not actually
/// time-locked. Callers that gate funds MUST pass the horizon-derived `min_t`
/// (`horizon::size_t(min_solve_secs, squarings_per_sec, s_max)`), not 1.
pub fn escrow_verify_min_t(
    public: &EscrowPublic,
    audit: &[usize],
    openings: &[Opening],
    min_t: u64,
) -> Result<Vec<usize>, EscrowError> {
    let order = curve_order();
    let share_point = decompress(&public.share_pub).ok_or(EscrowError::Malformed)?;
    let floor = min_t.max(1); // t == 0 is always rejected (verifiable-yet-unrecoverable)

    // Cut-and-choose needs at least two instances: with one instance there is
    // nothing to audit, so a dishonest escrower could commit `d` to one value
    // while hiding a different `r` in the puzzle and the binding check could
    // not catch it (no opened instance to cross-check the trapdoor against).
    if public.instances.len() < 2 {
        return Err(EscrowError::Malformed);
    }

    // S10: every modulus (kept ones included) must exceed the curve order.
    for (i, inst) in public.instances.iter().enumerate() {
        if inst.puzzle.n <= order {
            return Err(EscrowError::ModulusTooSmall);
        }
        // Escrow t=0 break: a zero-iteration puzzle has no time-lock and,
        // pre-fix, diverged between the audit (trapdoor) and recovery (solve)
        // paths — verifiable yet unrecoverable. Beyond that, `t < floor` voids
        // the time-lock horizon (N3): the puzzle solves too fast to protect the
        // backstop. Reject either, for every instance (kept ones included).
        if inst.puzzle.t < floor {
            return Err(EscrowError::TimeLockTooShort(i));
        }
    }

    if openings.len() != audit.len() {
        return Err(EscrowError::Malformed);
    }
    for (o, &i) in openings.iter().zip(audit) {
        if o.index != i || i >= public.instances.len() {
            return Err(EscrowError::Malformed);
        }
        let inst = &public.instances[i];
        // The factors must actually factor this instance's modulus, be
        // distinct, and be prime — otherwise the "trapdoor" proves nothing.
        if &o.p * &o.q != inst.puzzle.n
            || o.p == o.q
            || !num_bigint_dig::prime::probably_prime(&o.p, 32)
            || !num_bigint_dig::prime::probably_prime(&o.q, 32)
        {
            return Err(EscrowError::AuditFailed(i));
        }
        let r = Option::from(Scalar::from_canonical_bytes(o.r)).ok_or(EscrowError::Malformed)?;
        // The revealed r must open R_i…
        if (&r * ED25519_BASEPOINT_TABLE).compress().to_bytes() != inst.r_point {
            return Err(EscrowError::AuditFailed(i));
        }
        // …and the puzzle must honestly hide exactly r (checked in
        // milliseconds via the trapdoor).
        let td = Trapdoor {
            p: o.p.clone(),
            q: o.q.clone(),
        };
        match puzzle::open_with_trapdoor(&inst.puzzle, &td) {
            Some(v) if v == scalar_to_biguint(&r) => {}
            _ => return Err(EscrowError::AuditFailed(i)),
        }
    }

    // Kept instances: d_i·G == R_i + K binds each unopened instance to the
    // escrowed share without opening anything.
    let mut kept = Vec::new();
    for (i, inst) in public.instances.iter().enumerate() {
        if audit.contains(&i) {
            continue;
        }
        let d = Option::from(Scalar::from_canonical_bytes(inst.d)).ok_or(EscrowError::Malformed)?;
        let r_point = decompress(&inst.r_point).ok_or(EscrowError::Malformed)?;
        if &d * ED25519_BASEPOINT_TABLE != r_point + share_point {
            return Err(EscrowError::BindingFailed(i));
        }
        kept.push(i);
    }
    if kept.is_empty() {
        return Err(EscrowError::Malformed);
    }
    Ok(kept)
}

/// Recover the escrowed share from one kept instance by sequential squaring.
/// Verifies the result against `K` before returning it.
pub fn escrow_solve(public: &EscrowPublic, kept_index: usize) -> Result<Scalar, EscrowError> {
    let inst = public
        .instances
        .get(kept_index)
        .ok_or(EscrowError::Malformed)?;
    let r_big = puzzle::solve(&inst.puzzle);
    let r = biguint_to_scalar(&r_big).ok_or(EscrowError::ShareMismatch)?;
    let d: Scalar =
        Option::from(Scalar::from_canonical_bytes(inst.d)).ok_or(EscrowError::Malformed)?;
    let k = d - r;
    let share_point = decompress(&public.share_pub).ok_or(EscrowError::Malformed)?;
    if &k * ED25519_BASEPOINT_TABLE != share_point {
        return Err(EscrowError::ShareMismatch);
    }
    Ok(k)
}
