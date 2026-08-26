//! The RSW time-lock puzzle: `y = x0^(2^T) mod N`.
//!
//! The generator, knowing `φ(N)`, computes `y` in one modular exponentiation
//! (`2^T mod φ(N)`); everyone else needs `T` sequential modular squarings —
//! inherently serial work that parallel hardware cannot shortcut (only faster
//! sequential multipliers can, which the N3 margin absorbs).

use num_bigint_dig::{BigUint, RandPrime};
use num_traits::One;
use rand::RngCore;

/// A public puzzle instance hiding a value `v < N` as `c = (v + y) mod N`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Puzzle {
    pub n: BigUint,
    pub t: u64,
    pub x0: BigUint,
    pub c: BigUint,
}

/// The generator's trapdoor for one puzzle.
#[derive(Clone, Debug)]
pub struct Trapdoor {
    pub p: BigUint,
    pub q: BigUint,
}

impl Trapdoor {
    pub fn phi(&self) -> BigUint {
        (&self.p - 1u32) * (&self.q - 1u32)
    }
}

/// Generate a fresh modulus of `2·prime_bits` bits.
pub fn generate_modulus(rng: &mut (impl RngCore + rand::CryptoRng), prime_bits: usize) -> Trapdoor {
    let p = rng.gen_prime(prime_bits);
    let q = loop {
        let q = rng.gen_prime(prime_bits);
        if q != p {
            break q;
        }
    };
    Trapdoor { p, q }
}

/// Build a puzzle hiding `value` (must be `< N`). Fast path via the trapdoor.
pub fn make(
    rng: &mut (impl RngCore + rand::CryptoRng),
    trapdoor: &Trapdoor,
    t: u64,
    value: &BigUint,
) -> Puzzle {
    let n = &trapdoor.p * &trapdoor.q;
    assert!(value < &n, "value must be smaller than the modulus");
    let x0 = loop {
        let x = num_bigint_dig::RandBigInt::gen_biguint_below(rng, &n);
        if x > BigUint::one() {
            break x;
        }
    };
    let e = BigUint::from(2u32).modpow(&BigUint::from(t), &trapdoor.phi());
    let y = x0.modpow(&e, &n);
    let c = (value + y) % &n;
    Puzzle { n, t, x0, c }
}

/// Recover the hidden value using the trapdoor (fast — audit path).
pub fn open_with_trapdoor(puzzle: &Puzzle, trapdoor: &Trapdoor) -> Option<BigUint> {
    if &trapdoor.p * &trapdoor.q != puzzle.n {
        return None;
    }
    let e = BigUint::from(2u32).modpow(&BigUint::from(puzzle.t), &trapdoor.phi());
    let y = puzzle.x0.modpow(&e, &puzzle.n);
    Some(((&puzzle.c + &puzzle.n) - y % &puzzle.n) % &puzzle.n)
}

/// Recover the hidden value by `T` sequential squarings (slow — recovery path).
pub fn solve(puzzle: &Puzzle) -> BigUint {
    // Compute x0^(2^t) mod n by exactly `t` sequential squarings from x0.
    // Audit (escrow t=0 break): the previous form did one unconditional
    // squaring before looping `1..t`, so it computed x0^2 for BOTH t=0 and
    // t=1 — diverging from the trapdoor fast-path (x0^(2^t)) at t=0. That let
    // a t=0 escrow pass `escrow_verify` (which uses the trapdoor path) yet be
    // unrecoverable here. Squaring `t` times from x0 matches the trapdoor path
    // for every t, including 0 (y = x0) and 1 (y = x0^2).
    let mut y = &puzzle.x0 % &puzzle.n;
    for _ in 0..puzzle.t {
        y = (&y * &y) % &puzzle.n;
    }
    ((&puzzle.c + &puzzle.n) - y) % &puzzle.n
}

/// Measure this machine's sequential squaring rate (squarings/second) for a
/// modulus of the given size — the input to N3 horizon sizing.
pub fn calibrate(rng: &mut (impl RngCore + rand::CryptoRng), prime_bits: usize, samples: u64) -> f64 {
    let td = generate_modulus(rng, prime_bits);
    let n = &td.p * &td.q;
    let mut y = num_bigint_dig::RandBigInt::gen_biguint_below(rng, &n);
    let start = std::time::Instant::now();
    for _ in 0..samples {
        y = (&y * &y) % &n;
    }
    let secs = start.elapsed().as_secs_f64();
    if secs > 0.0 {
        samples as f64 / secs
    } else {
        f64::INFINITY
    }
}
