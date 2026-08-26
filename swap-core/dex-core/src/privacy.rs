//! I9: the swap-chaining privacy planner.
//!
//! XNO-leg privacy comes from routing through Monero itself: an XNO→XMR→XNO
//! round trip via DIFFERENT counterparties, so Monero's own privacy breaks
//! the Nano-side link — zero pool custody. Reinforced by fixed denominations
//! (amount decorrelation) and batch windows (timing decorrelation). This
//! module plans the route; execution rides the ordinary swap engine.

/// Standard denominations (raw XNO), largest first. Fixed sizes make every
//  chained swap look like every other.
pub const DENOMINATIONS: [u128; 6] = [
    100_000_000_000_000_000_000_000_000_000_000, // 100 XNO
    30_000_000_000_000_000_000_000_000_000_000,  // 30
    10_000_000_000_000_000_000_000_000_000_000,  // 10
    3_000_000_000_000_000_000_000_000_000_000,   // 3
    1_000_000_000_000_000_000_000_000_000_000,   // 1
    100_000_000_000_000_000_000_000_000_000,     // 0.1
];

/// One leg of the planned chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leg {
    pub denomination: u128,
    /// Batch window index this leg waits for (timing decorrelation).
    pub window: u64,
}

/// A planned round trip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub legs: Vec<Leg>,
    /// Untouched remainder below the smallest denomination (kept, not sent —
    /// sending odd change would undo the decorrelation).
    pub change: u128,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PlanError {
    /// Amount below the smallest denomination.
    TooSmall,
    /// Not enough distinct counterparties for the two hops of every leg.
    NotEnoughCounterparties { need: usize, have: usize },
}

/// Decompose `amount` into fixed denominations (greedy, largest first).
pub fn denominate(amount: u128) -> (Vec<u128>, u128) {
    let mut rest = amount;
    let mut out = Vec::new();
    for d in DENOMINATIONS {
        while rest >= d {
            out.push(d);
            rest -= d;
        }
    }
    (out, rest)
}

/// Plan a chain: each denomination becomes one leg, assigned to a batch
/// window round-robin from `start_window` over `window_count` windows.
/// `counterparties` is how many distinct peers the client currently sees
/// with adequate depth; each leg needs two (one per hop) that must differ.
pub fn plan(
    amount: u128,
    counterparties: usize,
    start_window: u64,
    window_count: u64,
) -> Result<Plan, PlanError> {
    let (denoms, change) = denominate(amount);
    if denoms.is_empty() {
        return Err(PlanError::TooSmall);
    }
    if counterparties < 2 {
        return Err(PlanError::NotEnoughCounterparties {
            need: 2,
            have: counterparties,
        });
    }
    let wc = window_count.max(1);
    let legs = denoms
        .into_iter()
        .enumerate()
        .map(|(i, denomination)| Leg {
            denomination,
            window: start_window + (i as u64 % wc),
        })
        .collect();
    Ok(Plan { legs, change })
}

/// The two hops of one leg must use different counterparties; given the
/// peer list (by index), pick a deterministic-but-spread assignment.
pub fn assign_hops(leg_index: usize, counterparties: usize) -> (usize, usize) {
    debug_assert!(counterparties >= 2);
    let a = leg_index % counterparties;
    let b = (a + 1 + (leg_index / counterparties) % (counterparties - 1)) % counterparties;
    (a, b)
}

/// The cost honesty line: a round trip pays two spreads plus two premiums.
/// Returns the estimated total cost fraction for display before commitment.
pub fn round_trip_cost(spread: f64, premium: f64) -> f64 {
    2.0 * (spread + premium)
}
