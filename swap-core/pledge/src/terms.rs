//! Pledge terms and their validation.

use num_bigint_dig::BigUint;

/// Basis points denominator.
pub const BPS: u128 = 10_000;

fn to_u128(v: BigUint) -> u128 {
    let b = v.to_bytes_le();
    if b.len() > 16 {
        return u128::MAX; // saturate (shouldn't happen for real penalties)
    }
    let mut a = [0u8; 16];
    a[..b.len()].copy_from_slice(&b);
    u128::from_le_bytes(a)
}

/// The agreed terms of one bilateral pledge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms {
    /// Party A's locked principal (raw XNO).
    pub principal_a: u128,
    /// Party B's locked principal (raw XNO).
    pub principal_b: u128,
    /// Early-exit penalty in basis points (1000 = 10%). Decays linearly to
    /// zero at maturity (H3): the *effective* penalty at exit time is
    /// `penalty_bps · remaining/term`.
    pub penalty_bps: u128,
    /// Unix seconds: when the pledge was opened.
    pub start: u64,
    /// Unix seconds: maturity — after this, the clean split is the outcome.
    pub maturity: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TermsError {
    ZeroPrincipal,
    /// Penalty above 50% is a hostage, not a commitment device.
    PenaltyTooLarge,
    BadTerm,
    /// The escrow puzzle must become solvable around maturity but the
    /// strict N3 rule failed for the given calibration.
    HorizonViolation,
}

impl Terms {
    pub fn validate(&self) -> Result<(), TermsError> {
        if self.principal_a == 0 || self.principal_b == 0 {
            return Err(TermsError::ZeroPrincipal);
        }
        if self.penalty_bps > BPS / 2 {
            return Err(TermsError::PenaltyTooLarge);
        }
        if self.maturity <= self.start {
            return Err(TermsError::BadTerm);
        }
        Ok(())
    }

    pub fn total(&self) -> u128 {
        self.principal_a + self.principal_b
    }

    /// Effective penalty (raw units) if `leaver` exits at `now` — the H3
    /// linear decay: full at start, zero at maturity, everyone gets a clean
    /// exit date.
    pub fn penalty_at(&self, principal: u128, now: u64) -> u128 {
        if now >= self.maturity {
            return 0;
        }
        let remaining = (self.maturity - now.max(self.start)) as u128;
        let term = (self.maturity - self.start) as u128;
        // Audit #7: multiply in 256-bit space to avoid u128 overflow
        // (principal is ~1e30 raw per XNO; the naive product overflows).
        let num = BigUint::from(principal) * BigUint::from(self.penalty_bps) * BigUint::from(remaining);
        let den = BigUint::from(BPS) * BigUint::from(term);
        to_u128(num / den)
    }

    /// The pre-signed chain uses the FULL penalty (worst case for the
    /// leaver); a decayed exit is negotiated as a cheaper cooperative close
    /// (the H3 exit auction, bounded above by this pre-signed path).
    pub fn full_penalty(&self, principal: u128) -> u128 {
        // Audit #7: 256-bit mul-div.
        let num = BigUint::from(principal) * BigUint::from(self.penalty_bps);
        to_u128(num / BigUint::from(BPS))
    }

    /// Size the escrow puzzle: it must NOT be solvable before maturity even
    /// on hardware `s_max`× faster. Returns the squaring count T for a
    /// machine calibrated at `squarings_per_sec` (N3-strict).
    pub fn escrow_t(&self, squarings_per_sec: f64, s_max: f64) -> u64 {
        let term = (self.maturity - self.start) as f64;
        // Audit #6: apply the N3 2× safety margin the horizon rule enforces,
        // so the escrow is not solvable before maturity even by hardware up to
        // 2× faster than the assumed s_max.
        puzzle_escrow::horizon::size_t(term, squarings_per_sec, s_max) * 2
    }
}
