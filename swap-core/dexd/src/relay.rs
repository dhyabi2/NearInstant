//! The relay core: a de-duplicating gossip node holding the deterministic
//! consolidated book. Transport-agnostic (the daemon wraps it in TCP);
//! everything here is pure and testable in-process.
//!
//! Honest by construction (B4): the relay only ever holds and forwards
//! *verified* signed orders — it cannot forge depth, and an order that fails
//! verification is dropped, not relayed. It never holds funds.

use std::collections::HashSet;

/// Audit #12: cap the book to bound memory against order-flood DoS.
const MAX_BOOK: usize = 50_000;
use std::sync::Mutex;

use dex_core::book::Book;
use dex_core::order::{Bytes32, SignedOrder};

/// One relay node's state.
pub struct Relay {
    book: Mutex<Book>,
    seen: Mutex<HashSet<Bytes32>>,
}

/// What to do with a just-received order.
#[derive(Debug, PartialEq, Eq)]
pub enum Ingest {
    /// New and valid — added to the book; the caller should flood it onward.
    Accepted,
    /// Already seen — do not re-flood (loop/dup suppression).
    Duplicate,
    /// Failed verification or expired — dropped, not relayed.
    Rejected,
}

impl Relay {
    pub fn new() -> Self {
        Self {
            book: Mutex::new(Book::default()),
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Ingest one order at time `now` with `pof_verified` metadata. Returns
    /// whether to flood it onward.
    pub fn ingest(&self, order: SignedOrder, now: u64, pof_verified: bool) -> Ingest {
        let hash = order.body.hash();
        {
            let mut seen = self.seen.lock().unwrap();
            if !seen.insert(hash) {
                return Ingest::Duplicate;
            }
        }
        let mut book = self.book.lock().unwrap();
        if book.len() >= MAX_BOOK {
            // Audit #12: refuse new orders past the cap (drop stale first via sweep).
            self.seen.lock().unwrap().remove(&hash);
            return Ingest::Rejected;
        }
        if book.insert(order, now, pof_verified) {
            Ingest::Accepted
        } else {
            // Roll back the seen-mark so a later valid re-broadcast can land.
            self.seen.lock().unwrap().remove(&hash);
            Ingest::Rejected
        }
    }

    /// Ingest an order carrying a Nano proof-of-funds. The order is marked
    /// `pof_verified` ONLY if the attached proof verifies and binds to this
    /// exact order (same maker + matching `pof_hash`); otherwise it enters
    /// flagged/unverified (B1: shown thinner, never hidden).
    pub fn ingest_with_pof(
        &self,
        order: SignedOrder,
        now: u64,
        proof: Option<&dex_core::pof::NanoFundsProof>,
    ) -> Ingest {
        let verified = proof
            .map(|p| p.verify(now) && p.matches_order(&order))
            .unwrap_or(false);
        self.ingest(order, now, verified)
    }

    /// Current Merkle root — the value a maker anchors and clients compare
    /// across relays (I7 consistency).
    pub fn merkle_root(&self) -> Bytes32 {
        self.book.lock().unwrap().merkle_root()
    }

    pub fn order_count(&self) -> usize {
        self.book.lock().unwrap().len()
    }

    /// Snapshot every live order's wire bytes (for serving a joining peer).
    pub fn snapshot(&self) -> Vec<Vec<u8>> {
        let book = self.book.lock().unwrap();
        book.all_orders().iter().map(|o| o.to_wire()).collect()
    }

    /// Drop expired orders and prune the dedup set (audit #12: `seen` must not
    /// grow unboundedly).
    ///
    /// Race F1: the previous version overwrote `seen` *wholesale* with the live
    /// book hashes. If an `ingest` had marked a hash in `seen` but not yet
    /// inserted the order into `book` (its `seen` lock is released before it
    /// takes the `book` lock), a `sweep` interleaving here would compute `live`
    /// without that order and drop its hash from `seen` — leaving the order in
    /// `book` but not `seen`, permanently breaking dedup and re-flooding the
    /// order on every future sighting (gossip amplification).
    ///
    /// Fixed by removing from `seen` ONLY the hashes actually dropped from
    /// `book`, all under the held `book` lock (the same `book`→`seen` order
    /// `ingest` uses when it holds both), so no in-flight insert is disturbed.
    pub fn sweep(&self, now: u64) -> usize {
        let mut book = self.book.lock().unwrap();
        let dropped = book.sweep_expired(now);
        if !dropped.is_empty() {
            let mut seen = self.seen.lock().unwrap();
            for hash in &dropped {
                seen.remove(hash);
            }
        }
        dropped.len()
    }
}

impl Default for Relay {
    fn default() -> Self {
        Self::new()
    }
}
