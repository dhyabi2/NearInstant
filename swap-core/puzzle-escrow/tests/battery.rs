//! Block 5 verification battery: the full escrow lifecycle (make → audit →
//! verify → solve → exact share back), every tamper path, the S10
//! modulus-vs-curve-order invariant, and the strict N3 horizon rule
//! (including the boundary-equality failure the executable model caught).

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use rand::rngs::OsRng;
use rand::RngCore;

use puzzle_escrow::escrow::{
    choose_audit, curve_order, escrow_make, escrow_open, escrow_solve, escrow_verify,
    escrow_verify_min_t, EscrowError,
};
use puzzle_escrow::horizon::{deadline_ok, max_deadline_secs, size_t};
use puzzle_escrow::puzzle::{self, Trapdoor};

// Small-but-valid test parameters: 130-bit primes give a 260-bit modulus
// (> the 253-bit curve order, satisfying S10) and T=512 squarings solve in
// milliseconds. Production would use 1024-bit primes and T in the billions.
const PRIME_BITS: usize = 130;
const T: u64 = 512;
const M: usize = 8;

fn rand_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

#[test]
fn single_instance_escrow_is_rejected() {
    // Cut-and-choose needs >= 2 instances; a 1-instance escrow has nothing to
    // audit, so a dishonest escrower could bind `d` to one value while hiding
    // a different `r`. The verifier must refuse it outright.
    let share = rand_scalar();
    let (public, _secret) = escrow_make(&mut OsRng, &share, 1, PRIME_BITS, T);
    assert_eq!(escrow_verify(&public, &[], &[]), Err(EscrowError::Malformed));
}

#[test]
fn escrow_lifecycle_recovers_exact_share() {
    let share = rand_scalar();
    let (public, secret) = escrow_make(&mut OsRng, &share, M, PRIME_BITS, T);

    let audit = choose_audit(&mut OsRng, M);
    assert_eq!(audit.len(), M / 2);
    let openings = escrow_open(&secret, &audit);
    let kept = escrow_verify(&public, &audit, &openings).expect("escrow verifies");
    assert_eq!(kept.len(), M - M / 2);

    // Recovery from any kept instance yields the exact share.
    for &i in &kept {
        let recovered = escrow_solve(&public, i).expect("solve");
        assert_eq!(recovered, share);
    }
    // And it opens the advertised public key.
    assert_eq!(
        (&share * ED25519_BASEPOINT_TABLE).compress().to_bytes(),
        public.share_pub
    );
}

#[test]
fn tampering_is_caught_at_every_surface() {
    let share = rand_scalar();
    let (public, secret) = escrow_make(&mut OsRng, &share, M, PRIME_BITS, T);
    let audit = choose_audit(&mut OsRng, M);
    let openings = escrow_open(&secret, &audit);
    let kept = escrow_verify(&public, &audit, &openings).expect("baseline verifies");

    // 1. A kept instance whose d doesn't bind to K: caught algebraically.
    {
        let mut bad = public.clone();
        let victim = kept[0];
        bad.instances[victim].d = rand_scalar().to_bytes();
        assert!(matches!(
            escrow_verify(&bad, &audit, &openings),
            Err(EscrowError::BindingFailed(i)) if i == victim
        ));
    }

    // 2. An audited instance whose puzzle hides the wrong value: caught by
    //    the trapdoor check.
    {
        let mut bad = public.clone();
        let victim = audit[0];
        let td = Trapdoor {
            p: openings[0].p.clone(),
            q: openings[0].q.clone(),
        };
        let wrong = puzzle::make(
            &mut OsRng,
            &td,
            T,
            &num_bigint_dig::BigUint::from(123456u64),
        );
        bad.instances[victim].puzzle = wrong;
        assert!(matches!(
            escrow_verify(&bad, &audit, &openings),
            Err(EscrowError::AuditFailed(i)) if i == victim
        ));
    }

    // 3. An opening with a fake factorization: caught.
    {
        let mut bad_openings = openings.clone();
        bad_openings[0].p += 2u32;
        assert!(matches!(
            escrow_verify(&public, &audit, &bad_openings),
            Err(EscrowError::AuditFailed(_))
        ));
    }

    // 4. A corrupted kept puzzle: verification cannot see it (that is the
    //    cut-and-choose deal), but recovery detects it against K instead of
    //    returning garbage.
    {
        let mut bad = public.clone();
        let victim = kept[0];
        bad.instances[victim].puzzle.c += 1u32;
        assert!(matches!(
            escrow_solve(&bad, victim),
            Err(EscrowError::ShareMismatch)
        ));
        // Other kept instances still recover the true share.
        assert_eq!(escrow_solve(&bad, kept[1]).unwrap(), share);
    }
}

/// S10: a modulus at or below the curve order is rejected outright — in the
/// executable model this silently truncated the share into garbage; here it
/// is a hard error before any value is trusted to it.
#[test]
fn small_modulus_is_rejected() {
    let share = rand_scalar();
    let (mut public, secret) = escrow_make(&mut OsRng, &share, M, PRIME_BITS, T);
    let audit = choose_audit(&mut OsRng, M);
    let openings = escrow_open(&secret, &audit);

    // Swap one instance's puzzle for one over a too-small modulus.
    let small_td = puzzle::generate_modulus(&mut OsRng, 100); // 200-bit N < 253-bit ℓ
    assert!((&small_td.p * &small_td.q) < curve_order());
    public.instances[0].puzzle = puzzle::make(
        &mut OsRng,
        &small_td,
        T,
        &num_bigint_dig::BigUint::from(7u32),
    );
    assert_eq!(
        escrow_verify(&public, &audit, &openings),
        Err(EscrowError::ModulusTooSmall)
    );
}

#[test]
fn trapdoor_and_sequential_solve_agree() {
    let td = puzzle::generate_modulus(&mut OsRng, PRIME_BITS);
    let value = num_bigint_dig::BigUint::from(0xDEADBEEFu64);
    let pz = puzzle::make(&mut OsRng, &td, T, &value);
    // Fast path (escrower) and slow path (solver) recover the same value.
    assert_eq!(puzzle::open_with_trapdoor(&pz, &td).unwrap(), value);
    assert_eq!(puzzle::solve(&pz), value);
    // A wrong trapdoor is refused.
    let other = puzzle::generate_modulus(&mut OsRng, PRIME_BITS);
    assert!(puzzle::open_with_trapdoor(&pz, &other).is_none());
}

/// N3: the horizon rule holds strictly — S08's catch: boundary equality fails.
#[test]
fn horizon_rule_is_strict() {
    let t_target = 7.0 * 24.0 * 3600.0; // a 7-day puzzle
    let s_max = 20.0;
    let boundary = t_target / (2.0 * s_max);

    assert!(deadline_ok(boundary - 1.0, t_target, s_max));
    assert!(!deadline_ok(boundary, t_target, s_max), "boundary equality must fail");
    assert!(!deadline_ok(boundary + 1.0, t_target, s_max));
    assert!(!deadline_ok(0.0, t_target, s_max));

    // Sizing round-trip: a T sized for a minimum solve time yields a positive
    // safe deadline consistent with the strict rule.
    let rate = puzzle::calibrate(&mut OsRng, PRIME_BITS, 2_000);
    assert!(rate > 0.0);
    let t = size_t(3600.0, rate, s_max);
    let max_dl = max_deadline_secs(t, rate, s_max);
    assert!(max_dl > 0.0);
    assert!(deadline_ok(max_dl * 0.99, t as f64 / rate, s_max));
}

/// Audit (escrow t=0 break): a t=0 puzzle has no time-lock and previously
/// diverged between the trapdoor audit path (x0^1) and the sequential solve
/// path (x0^2 — one unconditional squaring), so a malicious escrower could
/// pass `escrow_verify` yet leave every kept instance UNRECOVERABLE. Two locks
/// now: (1) `solve` squares exactly t times so it equals the trapdoor path for
/// all t including 0; (2) `escrow_verify` rejects t=0 outright.
#[test]
fn t_zero_escrow_is_rejected_and_solve_matches_trapdoor() {
    // (1) solve == open_with_trapdoor for t in {0,1,2,3}.
    for t in 0u64..=3 {
        let td = puzzle::generate_modulus(&mut OsRng, PRIME_BITS);
        let value = rand_scalar();
        let v = puzzle_escrow::escrow::scalar_to_biguint(&value);
        let p = puzzle::make(&mut OsRng, &td, t, &v);
        let solved = puzzle::solve(&p);
        let opened = puzzle::open_with_trapdoor(&p, &td).expect("trapdoor opens");
        assert_eq!(solved, opened, "solve and trapdoor diverge at t={t}");
        assert_eq!(solved, v, "recovered value wrong at t={t}");
    }

    // (2) An escrow built with t=0 is rejected by verification.
    let share = rand_scalar();
    let (public, secret) = escrow_make(&mut OsRng, &share, M, PRIME_BITS, 0);
    let audit = choose_audit(&mut OsRng, M);
    let openings = escrow_open(&secret, &audit);
    assert!(matches!(
        escrow_verify(&public, &audit, &openings),
        Err(EscrowError::TimeLockTooShort(_))
    ));
}

/// Audit (N3 horizon floor): escrow_verify_min_t rejects a backstop whose
/// puzzles solve faster than the horizon requires — a small non-zero t passes
/// the t!=0 check but voids the time-lock. The plain wrapper (floor=1) still
/// accepts anything with t>=1.
#[test]
fn escrow_verify_min_t_enforces_horizon_floor() {
    let share = rand_scalar();
    let (public, secret) = escrow_make(&mut OsRng, &share, M, PRIME_BITS, T); // T = 512
    let audit = choose_audit(&mut OsRng, M);
    let openings = escrow_open(&secret, &audit);

    // Floor at or below the actual t: verifies.
    assert!(escrow_verify_min_t(&public, &audit, &openings, T).is_ok());
    assert!(escrow_verify_min_t(&public, &audit, &openings, T - 1).is_ok());
    // Floor above t: rejected (solves too fast to protect the backstop).
    assert!(matches!(
        escrow_verify_min_t(&public, &audit, &openings, T + 1),
        Err(EscrowError::TimeLockTooShort(_))
    ));
    // The plain wrapper only enforces t != 0.
    assert!(escrow_verify(&public, &audit, &openings).is_ok());
}
