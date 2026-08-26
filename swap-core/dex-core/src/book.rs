//! B1/I7: the client-side consolidated order book.
//!
//! Built from verified signed orders received over any number of relays.
//! Deterministic: two clients holding the same order set render byte-equal
//! books and compute the same Merkle root (anchored periodically in Nano
//! `link` fields). Staleness is tracked per order and shown, never hidden;
//! proof-of-funds-verified orders carry full weight, unverified ones are
//! visible but flagged (B1: shown thinner, never hidden).

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use std::collections::BTreeMap;

use crate::order::{Bytes32, Side, SignedOrder};

/// One resting order plus book-side metadata.
#[derive(Clone, Debug)]
pub struct BookEntry {
    pub order: SignedOrder,
    /// When this client last saw the order re-gossiped/re-proved.
    pub last_seen: u64,
    /// Whether the attached proof-of-funds verified.
    pub pof_verified: bool,
}

/// The consolidated book. Keys sort deterministically:
/// (rate, tie-break hash) so every client agrees on ordering.
#[derive(Default)]
pub struct Book {
    entries: BTreeMap<(u128, Bytes32), BookEntry>,
}

/// One aggregated price level for display.
#[derive(Debug, PartialEq, Eq)]
pub struct Level {
    pub rate_pico: u128,
    /// PoF-verified depth at this level.
    pub verified_amount: u128,
    /// Unverified (flagged) depth at this level.
    pub unverified_amount: u128,
    /// Age of the stalest order contributing (for the staleness fade).
    pub max_age: u64,
}

impl Book {
    /// Insert (or refresh) a verified signed order. Returns false if the
    /// order fails verification — invalid orders never enter the book.
    pub fn insert(&mut self, order: SignedOrder, now: u64, pof_verified: bool) -> bool {
        if !order.verify(now) {
            return false;
        }
        let key = (order.body.rate_pico, order.tie_break_key());
        self.entries.insert(
            key,
            BookEntry {
                order,
                last_seen: now,
                pof_verified,
            },
        );
        true
    }

    /// Drop expired orders; returns how many were removed.
    /// Drop every expired order and return the hashes that were removed. The
    /// hashes let a caller prune a parallel dedup set to EXACTLY what was
    /// dropped (relay race F1) instead of overwriting it wholesale.
    pub fn sweep_expired(&mut self, now: u64) -> Vec<Bytes32> {
        let mut dropped = Vec::new();
        self.entries.retain(|(_, hash), e: &mut BookEntry| {
            if e.order.body.expiry > now {
                true
            } else {
                dropped.push(*hash);
                false
            }
        });
        dropped
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every live order, in deterministic book order.
    pub fn all_orders(&self) -> Vec<SignedOrder> {
        self.entries.values().map(|e| e.order.clone()).collect()
    }

    /// All entries of a side, best-priced first (deterministic).
    pub fn side(&self, side: Side) -> Vec<&BookEntry> {
        let mut v: Vec<&BookEntry> = self
            .entries
            .values()
            .filter(|e| e.order.body.side == side)
            .collect();
        // Sellers of XNO quote XMR-per-XNO: for a taker buying XNO, the
        // LOWEST rate is best. For sellers of XMR, the HIGHEST rate (more
        // XMR per XNO paid to the taker) is best.
        match side {
            Side::SellXno => {}
            Side::SellXmr => v.reverse(),
        }
        v
    }

    /// Aggregated ladder for one side (display: B1 PoF-weighted depth).
    pub fn levels(&self, side: Side, now: u64) -> Vec<Level> {        let mut out: Vec<Level> = Vec::new();
        for e in self.side(side) {
            let rate = e.order.body.rate_pico;
            let age = now.saturating_sub(e.last_seen);
            match out.last_mut() {
                Some(l) if l.rate_pico == rate => {
                    if e.pof_verified {
                        l.verified_amount += e.order.body.amount;
                    } else {
                        l.unverified_amount += e.order.body.amount;
                    }
                    l.max_age = l.max_age.max(age);
                }
                _ => out.push(Level {
                    rate_pico: rate,
                    verified_amount: if e.pof_verified { e.order.body.amount } else { 0 },
                    unverified_amount: if e.pof_verified { 0 } else { e.order.body.amount },
                    max_age: age,
                }),
            }
        }
        out
    }

    /// The deterministic Merkle root over all order hashes (sorted by book
    /// key) — the value anchored into Nano `link` fields (I7).
    pub fn merkle_root(&self) -> Bytes32 {
        let leaves: Vec<Bytes32> = self.entries.values().map(|e| e.order.body.hash()).collect();
        merkle_root(&leaves)
    }

    /// Inclusion proof for one order hash: the sibling path to the root.
    pub fn inclusion_proof(&self, order_hash: &Bytes32) -> Option<Vec<(Bytes32, bool)>> {
        let leaves: Vec<Bytes32> = self.entries.values().map(|e| e.order.body.hash()).collect();
        let idx = leaves.iter().position(|l| l == order_hash)?;
        Some(merkle_path(&leaves, idx))
    }

    /// A reference mid price (XMR per XNO) from the live book's best bid and
    /// best ask — a QUOTE, deliberately distinct from settled-trade market data
    /// (N6/B2): quotes never move the settled VWAP/candles, so wash-quoting the
    /// book cannot manufacture "market data". Used by makers/clients to anchor
    /// their own quoting and by the UI to show a live reference, never a
    /// "settled" price. `None` when the book has no depth on either side.
    pub fn mid(&self) -> Option<f64> {
        let ask = self
            .side(Side::SellXno)
            .first()
            .map(|e| e.order.body.rate_pico);
        let bid = self
            .side(Side::SellXmr)
            .first()
            .map(|e| e.order.body.rate_pico);
        match (bid, ask) {
            (Some(b), Some(a)) => Some((b as f64 + a as f64) / 2.0 / 1e12),
            (Some(b), None) => Some(b as f64 / 1e12),
            (None, Some(a)) => Some(a as f64 / 1e12),
            (None, None) => None,
        }
    }
}

fn node_hash(a: &Bytes32, b: &Bytes32) -> Bytes32 {
    let mut h = Blake2b::<U32>::new();
    h.update(b"node");
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// Root of a (padded) binary Blake2b tree; empty set roots to zero.
pub fn merkle_root(leaves: &[Bytes32]) -> Bytes32 {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<Bytes32> = leaves.to_vec();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(*layer.last().unwrap());
        }
        layer = layer
            .chunks(2)
            .map(|p| node_hash(&p[0], &p[1]))
            .collect();
    }
    layer[0]
}

fn merkle_path(leaves: &[Bytes32], mut idx: usize) -> Vec<(Bytes32, bool)> {
    let mut path = Vec::new();
    let mut layer: Vec<Bytes32> = leaves.to_vec();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(*layer.last().unwrap());
        }
        let sib = idx ^ 1;
        // (sibling, sibling-is-right)
        path.push((layer[sib], sib > idx));
        layer = layer.chunks(2).map(|p| node_hash(&p[0], &p[1])).collect();
        idx /= 2;
    }
    path
}

/// Verify an inclusion proof against an anchored root.
pub fn verify_inclusion(leaf: &Bytes32, path: &[(Bytes32, bool)], root: &Bytes32) -> bool {
    let mut acc = *leaf;
    for (sib, sib_right) in path {
        acc = if *sib_right {
            node_hash(&acc, sib)
        } else {
            node_hash(sib, &acc)
        };
    }
    acc == *root
}
