//! N1 journal anchoring: the Nano chain as a free trustless record of the
//! channel's state sequence.
//!
//! After accepting state `i`, the taker (or either party) broadcasts a
//! **1-raw send whose destination account IS the state hash** — the standard
//! Nano data-anchoring shape. Anyone replaying the anchoring account's chain
//! recovers the exact ordered list of state hashes. At recovery, a
//! counterparty serving an old state is convicted by one comparison: the
//! served state's hash appears earlier than the journal's tip.

use nano_ceremony::block::{StateBlock, Subtype};
use nano_ceremony::Bytes32;

/// The hash a state anchors under: any collision-resistant digest of the
/// state both parties compute identically. We use the state's signable hash
/// (`SignedState::msg`), which already commits to the split.
pub fn anchor_target(state_msg: &[u8; 32]) -> Bytes32 {
    *state_msg
}

/// Build the (unsigned) anchor block: a 1-raw send from `journal_account`
/// (frontier `previous`, balance `balance_before`) to the state hash.
pub fn anchor_block(
    journal_account: Bytes32,
    previous: Bytes32,
    representative: Bytes32,
    balance_before: u128,
    state_msg: &[u8; 32],
) -> Option<StateBlock> {
    // Audit #20: underflow guard — cannot anchor from a zero-balance account.
    let balance = balance_before.checked_sub(1)?;
    Some(StateBlock {
        account: journal_account,
        previous,
        representative,
        balance,
        link: anchor_target(state_msg),
        subtype: Subtype::Send,
    })
}

/// The signed anchor payload: the state hash committed together with its
/// monotone channel index, so ordering is by index — not by on-chain
/// position — defeating the re-anchor-stale-as-tip attack (audit #3). The
/// index is encoded into the anchor amount's low bits is NOT possible on a
/// 1-raw send, so the index travels in the state hash preimage: callers pass
/// `(state_index, state_msg)` and we record both. Anchors are replayed and
/// judged by the highest committed index.
pub fn anchor_with_index(state_index: u64, state_msg: &[u8; 32]) -> ([u8; 32], u64) {
    (anchor_target(state_msg), state_index)
}

/// Replay a journal account's send chain into the ordered anchor list.
/// `blocks` is the account's block sequence (oldest first) as read from any
/// node; non-anchor blocks (receives, changes, larger sends) are skipped.
pub fn replay(blocks: &[StateBlock]) -> Vec<Bytes32> {
    let mut anchors = Vec::new();
    let mut prev_balance: Option<u128> = None;
    for b in blocks {
        if let Some(pb) = prev_balance {
            if b.subtype == Subtype::Send && pb == b.balance + 1 {
                anchors.push(b.link);
            }
        }
        prev_balance = Some(b.balance);
    }
    anchors
}

/// Recovery verdict for a state served by the counterparty.
#[derive(Debug, PartialEq, Eq)]
pub enum ServeVerdict {
    /// The served state is the journal tip — accept it.
    Latest,
    /// The served state appears in the journal but is not the tip: the
    /// counterparty is lying by omission. The journal position is returned
    /// as evidence.
    Stale { served_pos: usize, tip_pos: usize },
    /// The served state never hit the journal (either newer than the last
    /// anchor — acceptable if anchoring lags — or fabricated).
    Unanchored,
}

/// Judge a served state against the set of (state_index, state_hash) anchors
/// recovered from the signed state log. Ordering is by the monotone
/// `state_index` (audit #3), NOT by on-chain position — so a counterparty
/// re-broadcasting an old state's hash as a later on-chain send cannot make
/// the stale state the "tip".
///
/// Audit (channel-journal break): the served state's index is looked up FROM
/// THE TRUSTED ANCHOR LOG by matching its hash — never taken from a
/// counterparty-supplied index. An earlier version trusted a `served_index`
/// argument in the presence test, which let a maker attach a bogus higher
/// index to a genuinely-stale hash so the verdict collapsed to `Unanchored`
/// (or `Latest`), laundering the stale serve out of conviction — a regression
/// below the legacy positional judge. The index of a state is committed inside
/// its own hash preimage (`expected_state_msg`), so the honest party's log is
/// authoritative for it; the counterparty only supplies the hash.
pub fn judge_served_indexed(anchors: &[(u64, [u8; 32])], served_msg: &[u8; 32]) -> ServeVerdict {
    let target = anchor_target(served_msg);
    let tip_index = anchors.iter().map(|(i, _)| *i).max();
    // Look the served hash up in the trusted log and use ITS recorded index.
    // First match by hash wins, so a forged duplicate anchor appended at a
    // higher index cannot shadow the real (lower) one.
    let served_index = anchors
        .iter()
        .find(|(_, h)| *h == target)
        .map(|(i, _)| *i);
    match (served_index, tip_index) {
        (Some(i), Some(tip)) if i == tip => ServeVerdict::Latest,
        (Some(i), Some(tip)) => ServeVerdict::Stale {
            served_pos: i as usize,
            tip_pos: tip as usize,
        },
        _ => ServeVerdict::Unanchored,
    }
}

/// Legacy positional judge (kept for the old anchor list); prefer
/// `judge_served_indexed`. Positional ordering is vulnerable to re-anchoring
/// (audit #3) and must not be relied on for conviction.
pub fn judge_served_state(anchors: &[Bytes32], served_msg: &[u8; 32]) -> ServeVerdict {
    let target = anchor_target(served_msg);
    match anchors.iter().rposition(|a| *a == target) {
        Some(pos) if pos + 1 == anchors.len() => ServeVerdict::Latest,
        Some(pos) => ServeVerdict::Stale { served_pos: pos, tip_pos: anchors.len() - 1 },
        None => ServeVerdict::Unanchored,
    }
}
