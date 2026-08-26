//! The I3 guard ladder.
//!
//! Invariant (I3): a completed refund signature may never coexist with a live
//! claim window. The ladder enforces the broadcast discipline around it: at
//! setup both parties pre-sign a chain of representative-change blocks
//! (`guard_1.previous = frontier`, `guard_{k+1}.previous = guard_k.hash()`).
//! Before any secret-revealing broadcast, the claimant broadcasts the next
//! rung — it moves nothing and reveals nothing, but advances the frontier,
//! which invalidates *every* signature made against a stale frontier. The
//! claim is then signed against the fresh frontier, on which it is the only
//! signature that has ever existed. Losing the race for a rung is a clean
//! abort: the rung itself discloses nothing.

use crate::block::StateBlock;
use crate::Bytes32;

/// A pre-signed rung: a change block plus its joint signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rung {
    pub block: StateBlock,
    pub signature: [u8; 64],
}

impl Rung {
    /// Verify the rung is a well-formed guard for this account: a value-free
    /// change block whose signature verifies under the joint key.
    pub fn verify(&self, account: &Bytes32, balance: u128) -> bool {
        self.block.account == *account
            && self.block.balance == balance
            && self.block.link == [0u8; 32]
            && self.block.subtype == crate::block::Subtype::Change
            && signing::nano_verify::verify(account, &self.block.hash(), &self.signature)
    }
}

/// Build the unsigned rung chain from a frontier. Both parties MUST derive
/// the identical chain (same frontier, representative, balance, count) and
/// jointly sign every rung *before any funds move*; refusal to sign the
/// ladder cancels the swap at zero cost.
pub fn build_rungs(
    account: Bytes32,
    frontier: Bytes32,
    representative: Bytes32,
    balance: u128,
    count: usize,
) -> Vec<StateBlock> {
    let mut rungs = Vec::with_capacity(count);
    let mut previous = frontier;
    for _ in 0..count {
        let block = StateBlock::change(account, previous, representative, balance);
        previous = block.hash();
        rungs.push(block);
    }
    rungs
}

/// A fully-signed ladder held by a claimant.
#[derive(Clone, Debug)]
pub struct GuardLadder {
    account: Bytes32,
    balance: u128,
    rungs: Vec<Rung>,
}

impl GuardLadder {
    /// Assemble and verify a ladder from signed rungs. Every rung must verify
    /// and must chain (`rung_{k+1}.previous == rung_k.hash()`).
    pub fn new(account: Bytes32, balance: u128, rungs: Vec<Rung>) -> Option<Self> {
        for pair in rungs.windows(2) {
            if pair[1].block.previous != pair[0].block.hash() {
                return None;
            }
        }
        if !rungs.iter().all(|r| r.verify(&account, balance)) {
            return None;
        }
        Some(Self {
            account,
            balance,
            rungs,
        })
    }

    /// Audit #10 (enforced path): build a ladder whose balance is taken from
    /// the node's CONFIRMED frontier balance, not from a caller-supplied
    /// figure. This is the only constructor a claimant should use before
    /// trusting a counterparty's rungs as value-free: if the rungs were built
    /// against any other balance, `Rung::verify` fails here and the ladder is
    /// rejected — closing the burn-ladder attack where rungs carry a balance
    /// below the true frontier (each broadcast would send the difference to the
    /// zero account). Returns `None` if the node cannot report a confirmed
    /// balance, in which case the ladder must not be trusted.
    pub fn from_confirmed(
        account: Bytes32,
        node: &dyn crate::broadcast::NanoNode,
        rungs: Vec<Rung>,
    ) -> Option<Self> {
        let confirmed = node.frontier_balance(&account)?;
        let ladder = Self::new(account, confirmed, rungs)?;
        // Belt-and-braces: the assembled ladder's balance IS the confirmed one.
        debug_assert!(ladder.matches_frontier_balance(confirmed));
        // Audit (race M4): binding the balance is not enough — the ladder must
        // also chain to the account's CURRENT frontier hash. If the frontier
        // advanced (e.g. a receive) since the rungs were negotiated while the
        // balance stayed the same, the base rung targets a stale frontier and
        // the ladder is already dead: `next_rung(current)` is `None`. Reject it
        // here at build time instead of silently deferring the failure to
        // broadcast time (where the ledger's one-block-per-frontier rule would
        // reject the stale rung).
        let current_frontier = node.frontier(&account)?;
        ladder.next_rung(&current_frontier)?;
        Some(ladder)
    }

    /// The rung to broadcast when the frontier is `frontier`, if the ladder
    /// has one. `None` means the frontier is not on this ladder's path —
    /// either the ladder is exhausted or the chain moved elsewhere (a new
    /// ladder must be negotiated before relying on guards again).
    pub fn next_rung(&self, frontier: &Bytes32) -> Option<&Rung> {
        self.rungs.iter().find(|r| r.block.previous == *frontier)
    }

    /// Rungs remaining after (and including) the one for `frontier`.
    pub fn remaining(&self, frontier: &Bytes32) -> usize {
        match self.rungs.iter().position(|r| r.block.previous == *frontier) {
            Some(i) => self.rungs.len() - i,
            None => 0,
        }
    }

    pub fn account(&self) -> &Bytes32 {
        &self.account
    }

    pub fn balance(&self) -> u128 {
        self.balance
    }

    /// Audit #10: cross-check that the balance the ladder was built with is
    /// the account's TRUE confirmed frontier balance. A ladder built with a
    /// balance below the real frontier balance would be a chain of
    /// jointly-signed BURNS (the ledger treats any balance decrease as a send
    /// to `link`, and rungs link to the zero account). Callers MUST run this
    /// against a confirmed node before trusting the ladder as value-free.
    pub fn matches_frontier_balance(&self, frontier_balance: u128) -> bool {
        self.balance == frontier_balance
    }
}
