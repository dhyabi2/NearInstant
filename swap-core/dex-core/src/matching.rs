//! B8: fairness without a sequencer.
//!
//! Matching is taker-choice; what the protocol adds is mechanics that keep
//! races honest: commit-reveal taking (terms hidden until the race starts),
//! single-use tickets (one executor per quote), and maker-side FCFS signed
//! receipts (verifiable arrival order — the only arrival evidence that binds
//! anyone; client clocks are free to lie and get no standing).

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use std::collections::HashSet;

use crate::book::{Book, BookEntry};
use crate::order::{Bytes32, Side};

/// Best-execution selection: the entries a taker should hit for `amount`,
/// walking best-priced levels first (deterministic ordering shared by every
/// client — no hidden preference).
///
/// Self-match break: a taker's own resting orders are skipped. Matching your
/// own quote is a wash trade — it produces settled trades that are the only
/// feed for the market/ticker/VWAP, the earn quoting engine and the triggers,
/// so allowing it lets a single party manufacture price and volume out of
/// nothing. The `taker` key is compared against each entry's maker.
pub fn select_for_amount<'a>(
    book: &'a Book,
    side: Side,
    mut amount: u128,
    taker: &Bytes32,
) -> Vec<(&'a BookEntry, u128)> {
    let mut picks = Vec::new();
    for e in book.side(side) {
        if amount == 0 {
            break;
        }
        if is_self_match(e, taker) {
            continue;
        }
        let take = amount.min(e.order.body.amount);
        picks.push((e, take));
        amount -= take;
    }
    picks
}

/// Whether hitting `entry` with `taker` would be a self-trade (wash). The
/// single source of truth for the self-match rule — also enforced at reveal.
pub fn is_self_match(entry: &BookEntry, taker: &Bytes32) -> bool {
    entry.order.body.maker == *taker
}

/// A taker's commitment to take a quote: hash of (order, taker key, salt).
/// Gossiped first; the reveal follows. Nobody can front-run terms they
/// cannot see.
pub fn commit(order_hash: &Bytes32, taker: &Bytes32, salt: &Bytes32) -> Bytes32 {
    let mut h = Blake2b::<U32>::new();
    h.update(b"take-commit");
    h.update(order_hash);
    h.update(taker);
    h.update(salt);
    h.finalize().into()
}

/// Check a reveal against a prior commitment.
pub fn verify_reveal(
    commitment: &Bytes32,
    order_hash: &Bytes32,
    taker: &Bytes32,
    salt: &Bytes32,
) -> bool {
    commit(order_hash, taker, salt) == *commitment
}

/// Maker-side single-use ticket registry: a quote is bound to the first
/// valid reveal; every later claim is refused.
#[derive(Default)]
pub struct TicketRegistry {
    used: HashSet<Bytes32>,
}

impl TicketRegistry {
    /// Attempt to consume the ticket for `order_hash`. True exactly once.
    pub fn consume(&mut self, order_hash: &Bytes32) -> bool {
        self.used.insert(*order_hash)
    }
}

/// A maker-signed arrival receipt: the verifiable FCFS queue position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub order_hash: Bytes32,
    pub taker: Bytes32,
    /// Maker-local arrival sequence number (monotone).
    pub seq: u64,
    pub maker: Bytes32,
    pub signature: [u8; 64],
}

pub fn receipt_message(order_hash: &Bytes32, taker: &Bytes32, seq: u64) -> Vec<u8> {
    let mut m = b"XNOXMR-RECEIPT-v1\0".to_vec();
    m.extend_from_slice(order_hash);
    m.extend_from_slice(taker);
    m.extend_from_slice(&seq.to_be_bytes());
    m
}

impl Receipt {
    pub fn verify(&self) -> bool {
        signing::nano_verify::verify(
            &self.maker,
            &receipt_message(&self.order_hash, &self.taker, self.seq),
            &self.signature,
        )
    }
}

/// Audit a maker's receipts against its settlements: every settled taker
/// must hold the LOWEST outstanding sequence at its settlement time, or the
/// maker provably reordered (the B8 public audit trail). Returns the first
/// violation as (settled_seq, skipped_seq).
pub fn audit_fcfs(receipts: &[Receipt], settled_order: &[Bytes32]) -> Option<(u64, u64)> {
    // Map order hash -> receipt seq (receipts must be verified by caller).
    let mut pending: Vec<&Receipt> = receipts.iter().collect();
    // Audit (FCFS-determinism break): sort by the FULL canonical key
    // (seq, order_hash), not seq alone. A plain `sort_by_key(seq)` is stable,
    // so two receipts sharing a seq kept the caller's input order and the
    // verdict flipped with the receipt vector's ordering — the same evidence
    // convicting or acquitting depending on argument order. The order_hash
    // tie-break makes the ordering total and input-independent.
    pending.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.order_hash.cmp(&b.order_hash)));
    // A maker MUST issue strictly-monotone, unique arrival sequences. Two
    // receipts with the same seq means the maker told two takers each "you
    // were first" — itself a provable FCFS violation, reported as the
    // colliding seq against itself (independent of settlement order).
    for w in pending.windows(2) {
        if w[0].seq == w[1].seq {
            return Some((w[0].seq, w[1].seq));
        }
    }
    for settled in settled_order {
        // Audit #8: a settled order with NO receipt is itself a reordering
        // violation (the maker skipped the FCFS receipt to escape audit).
        let Some(pos) = pending.iter().position(|r| r.order_hash == *settled) else {
            let lowest = pending.first().map(|r| r.seq).unwrap_or(0);
            return Some((0, lowest));
        };
        if pos != 0 {
            return Some((pending[pos].seq, pending[0].seq));
        }
        pending.remove(0);
    }
    None
}
