//! Eclipse-defense layers (R14) — make a lying view of the Monero chain cost
//! real hashpower, not mere collusion, WITHOUT full RandomX verification
//! (which browsers and small VPSes cannot afford).
//!
//! These are pure decision functions over data the caller fetches from the
//! daemon quorum; they hold no network code, so they unit-test deterministically.
//! Three independent checks compose (all must pass):
//!
//! 1. [`extends_checkpoint`] — a release-pinned recent block hash must appear
//!    in the served chain at its height. Rewriting history before that point
//!    requires out-mining the network since the checkpoint. Checkpoints ship
//!    with each release (immutable facts, not a live service).
//!
//! 2. [`cumulative_difficulty_consistent`] — a node's claimed cumulative
//!    difficulty must equal its previous cumulative difficulty plus the sum of
//!    the per-block difficulties it served. A node inflating its chain weight
//!    to look "heaviest" without the blocks to back it is caught here.
//!
//! 3. [`quorum_agrees`] — independent nodes (and, via `transport::socks`, the
//!    same node over clearnet AND Tor) must agree on the block hash at a
//!    height. Per-route lying is exposed because an eclipser would have to
//!    control every route of every node simultaneously.
//!
//! The RSW horizon rule already bounds the *exploitation* window economically;
//! these layers raise the *cost* of even attempting the lie.

/// A pinned checkpoint shipped with a release: an immutable `(height, hash)`
/// fact of Monero history the served chain must extend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub hash: [u8; 32],
}

/// A block header as reported by a daemon (only the fields these checks need).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderClaim {
    pub height: u64,
    pub hash: [u8; 32],
    /// This block's own difficulty.
    pub difficulty: u128,
    /// The chain's cumulative difficulty AS OF this block, per the daemon.
    pub cumulative_difficulty: u128,
}

/// Layer 1: the served chain includes the pinned checkpoint block at its
/// height. `at_height` is the served hash the caller fetched for
/// `checkpoint.height` (e.g. via `get_block_header_by_height`).
pub fn extends_checkpoint(checkpoint: &Checkpoint, at_height: &[u8; 32]) -> bool {
    *at_height == checkpoint.hash
}

/// Layer 2: a contiguous run of headers is internally consistent — each
/// block's cumulative difficulty is the previous one's plus this block's
/// difficulty. `headers` must be sorted ascending by height and contiguous.
/// Returns `false` on any gap, ordering error, or accounting mismatch.
pub fn cumulative_difficulty_consistent(headers: &[HeaderClaim]) -> bool {
    for pair in headers.windows(2) {
        let (prev, cur) = (&pair[0], &pair[1]);
        if cur.height != prev.height + 1 {
            return false; // gap or out of order
        }
        match prev.cumulative_difficulty.checked_add(cur.difficulty) {
            Some(expected) if expected == cur.cumulative_difficulty => {}
            _ => return false,
        }
    }
    !headers.is_empty()
}

/// Layer 3: every independent view agrees on the block hash at a height.
/// `views` are the hashes fetched for one height across nodes/routes. Requires
/// at least `min_views` of them and unanimous agreement (a settlement read is
/// fail-closed: any disagreement is a stop, not a majority vote).
pub fn quorum_agrees(views: &[[u8; 32]], min_views: usize) -> bool {
    if views.len() < min_views || views.is_empty() {
        return false;
    }
    let first = views[0];
    views.iter().all(|v| *v == first)
}

/// Compose all three layers for a settlement-grade acceptance decision at the
/// swap's target height. Returns `Ok(())` only if every layer passes.
pub fn accept_chain(
    checkpoint: &Checkpoint,
    checkpoint_height_hash: &[u8; 32],
    headers: &[HeaderClaim],
    target_height_views: &[[u8; 32]],
    min_views: usize,
) -> Result<(), EclipseError> {
    if !extends_checkpoint(checkpoint, checkpoint_height_hash) {
        return Err(EclipseError::CheckpointMismatch);
    }
    if !cumulative_difficulty_consistent(headers) {
        return Err(EclipseError::DifficultyInconsistent);
    }
    if !quorum_agrees(target_height_views, min_views) {
        return Err(EclipseError::QuorumDisagrees);
    }
    Ok(())
}

/// Why a chain view was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EclipseError {
    /// The served chain does not contain the pinned checkpoint block.
    CheckpointMismatch,
    /// A node's cumulative-difficulty accounting does not add up.
    DifficultyInconsistent,
    /// Independent views disagree on the block hash at the target height.
    QuorumDisagrees,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(height: u64, diff: u128, cum: u128) -> HeaderClaim {
        HeaderClaim { height, hash: [height as u8; 32], difficulty: diff, cumulative_difficulty: cum }
    }

    #[test]
    fn checkpoint_must_match() {
        let cp = Checkpoint { height: 3_000_000, hash: [0xAB; 32] };
        assert!(extends_checkpoint(&cp, &[0xAB; 32]));
        assert!(!extends_checkpoint(&cp, &[0xAC; 32]));
    }

    #[test]
    fn difficulty_accounting_catches_inflation() {
        // Honest run: cum grows by exactly each block's difficulty.
        let good = [hdr(100, 0, 1_000), hdr(101, 500, 1_500), hdr(102, 500, 2_000)];
        assert!(cumulative_difficulty_consistent(&good));

        // A node inflates cumulative weight without the difficulty to back it.
        let inflated = [hdr(100, 0, 1_000), hdr(101, 500, 9_999)];
        assert!(!cumulative_difficulty_consistent(&inflated));

        // A gap in heights is rejected.
        let gap = [hdr(100, 0, 1_000), hdr(102, 500, 1_500)];
        assert!(!cumulative_difficulty_consistent(&gap));

        assert!(!cumulative_difficulty_consistent(&[]), "empty is not consistent");
    }

    #[test]
    fn quorum_is_unanimous_and_sized() {
        assert!(quorum_agrees(&[[7; 32], [7; 32]], 2));
        assert!(!quorum_agrees(&[[7; 32]], 2), "too few views");
        assert!(!quorum_agrees(&[[7; 32], [8; 32]], 2), "disagreement fails closed");
    }

    #[test]
    fn accept_chain_requires_all_layers() {
        let cp = Checkpoint { height: 100, hash: [100; 32] };
        let headers = [hdr(100, 0, 1_000), hdr(101, 500, 1_500)];
        let views = [[101u8; 32], [101u8; 32]];
        assert_eq!(accept_chain(&cp, &[100; 32], &headers, &views, 2), Ok(()));

        // Break each layer in turn.
        assert_eq!(
            accept_chain(&cp, &[99; 32], &headers, &views, 2),
            Err(EclipseError::CheckpointMismatch)
        );
        let bad_diff = [hdr(100, 0, 1_000), hdr(101, 500, 8_888)];
        assert_eq!(
            accept_chain(&cp, &[100; 32], &bad_diff, &views, 2),
            Err(EclipseError::DifficultyInconsistent)
        );
        assert_eq!(
            accept_chain(&cp, &[100; 32], &headers, &[[101u8; 32], [9u8; 32]], 2),
            Err(EclipseError::QuorumDisagrees)
        );
    }
}
