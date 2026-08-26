//! Monero dynamic-fee handling for state/sweep transactions.
//!
//! Monero fees are dynamic (priced per transaction *weight*), and there is no
//! RBF and only awkward CPFP — a too-low fee is a stuck transaction. For an
//! atomic swap that has three consequences this module makes safe:
//!
//! 1. **Net-of-fee math.** A joint output of `amount` can only pay
//!    `amount - fee`; signing a transaction whose output would underflow the
//!    fee is refused ([`net_output_after_fee`]).
//! 2. **Fresh fee on the happy path.** The cooperative sweep is co-signed live
//!    (see [`crate::cosign`]), so its fee is estimated at settlement time from
//!    the daemon's current [`FeeRate`] — never a stale baked-in constant.
//! 3. **Overpay the refund.** The unilateral refund/backstop is the rare abort
//!    path and cannot be re-fee'd once broadcast, so it is priced at
//!    [`Priority::High`] with a safety margin so it confirms before its
//!    time-lock matures ([`refund_fee`]).
//!
//! The weight estimator uses documented ring-16 CLSAG + Bulletproof+ constants;
//! it is intentionally a slight over-estimate (overpaying fee is the safe
//! direction) and should be calibrated against real serialized transactions
//! before mainnet. The authoritative fee always comes from a live daemon's
//! `get_fee_estimate` — modelled here by [`FeeRate`].

/// Confirmation-priority levels, matching the four fee tiers a Monero daemon
/// returns from `get_fee_estimate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low = 0,
    Normal = 1,
    High = 2,
    Highest = 3,
}

/// A daemon fee estimate: the per-weight fee for each priority tier and the
/// quantization mask (final fees are rounded up to a multiple of the mask).
/// Mirrors the `fees` array + `quantization_mask` of the `get_fee_estimate`
/// RPC. Obtain it from a live node via a [`FeeSource`]; the arithmetic below is
/// pure and identical to what a wallet does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeRate {
    /// Fee in atomic units (piconero) per weight unit, indexed by [`Priority`].
    pub per_weight: [u64; 4],
    /// Fees are rounded UP to a multiple of this (piconero). Never zero.
    pub quantization_mask: u64,
}

impl FeeRate {
    /// A conservative fallback rate for offline estimation when a daemon is
    /// unreachable. Deliberately higher than typical mainnet so an estimate is
    /// never *under* the real network minimum. NOT a substitute for a live
    /// `get_fee_estimate` — the happy path must use the real rate.
    pub const FALLBACK: FeeRate = FeeRate {
        // ~ historical low tier is ~20k piconero/weight; scale the tiers.
        per_weight: [20_000, 100_000, 500_000, 2_000_000],
        quantization_mask: 10_000,
    };

    /// The per-weight fee for `priority`.
    pub fn per_weight(&self, priority: Priority) -> u64 {
        self.per_weight[priority as usize]
    }
}

/// Something that can fetch the current [`FeeRate`] from a Monero node
/// (`get_fee_estimate`). Implemented by the daemon RPC client; kept as a trait
/// so the fee math stays node-agnostic and unit-testable.
pub trait FeeSource {
    fn fee_rate(&self) -> Option<FeeRate>;
}

// --- transaction weight -----------------------------------------------------

/// Ring size Monero mandates (consensus): 16 (15 decoys + 1 real).
pub const RING_SIZE: usize = 16;

// Documented ring-16 CLSAG + BP+ serialized-weight constants (piconero-free,
// bytes). Slight over-estimates: overpaying fee is the safe direction.
const TX_BASE_WEIGHT: u64 = 96; // version, unlock_time, rct type, fee varint, tx_extra baseline
const PER_INPUT_WEIGHT: u64 = 664; // vin + key image(32) + ring-16 CLSAG(576) + pseudo-out(32) + offsets
const PER_OUTPUT_WEIGHT: u64 = 76; // one-time key(32) + ecdhInfo amount(8) + outPk commitment(32) + varints

/// Bulletproof+ range-proof weight for `n_outputs` (padded up to a power of two).
fn bulletproof_plus_weight(n_outputs: u64) -> u64 {
    // BP+ proof size ≈ 32·(2·log2(64·pad) + 3) bytes; pad = next power of two.
    let pad = n_outputs.max(1).next_power_of_two();
    let bits = 64 * pad;
    let log2 = 64 - (bits.leading_zeros() as u64) - 1; // floor(log2(bits))
    32 * (2 * log2 + 6) // +6 covers the fixed L/R/A/A1/B/r1/s1/d1 elements
}

/// Estimate the serialized weight of a CLSAG transaction with `num_inputs`
/// ring-16 inputs and `num_outputs` outputs. For a Monero transaction
/// `num_outputs >= 2` always (a recipient + a change/dummy output).
pub fn tx_weight(num_inputs: u64, num_outputs: u64) -> u64 {
    debug_assert!(num_inputs >= 1 && num_outputs >= 2);
    TX_BASE_WEIGHT
        + PER_INPUT_WEIGHT * num_inputs
        + PER_OUTPUT_WEIGHT * num_outputs
        + bulletproof_plus_weight(num_outputs)
}

/// Weight of the common state-sweep shape: one joint input, two outputs
/// (recipient + change). The atomic-swap default.
pub fn sweep_weight() -> u64 {
    tx_weight(1, 2)
}

// --- fee computation --------------------------------------------------------

/// Round `fee` UP to the next multiple of `mask` (Monero fee quantization).
fn quantize_up(fee: u64, mask: u64) -> u64 {
    let mask = mask.max(1);
    // ceil(fee / mask) * mask, overflow-safe.
    match fee.checked_add(mask - 1) {
        Some(s) => (s / mask) * mask,
        None => (fee / mask) * mask + mask, // saturating: fee is already near u64::MAX
    }
}

/// The fee for a transaction of `weight` at `priority`, quantized like a wallet.
pub fn estimate_fee(rate: &FeeRate, weight: u64, priority: Priority) -> u64 {
    let raw = rate.per_weight(priority).saturating_mul(weight);
    quantize_up(raw, rate.quantization_mask)
}

/// The fee for the cooperative sweep at a chosen priority (fresh, live rate).
pub fn sweep_fee(rate: &FeeRate, priority: Priority) -> u64 {
    estimate_fee(rate, sweep_weight(), priority)
}

/// The refund/backstop fee: [`Priority::High`] plus a safety margin, because
/// the refund is pre-signed, cannot be re-fee'd, and must confirm before its
/// time-lock matures. `margin_bps` is added in basis points (e.g. 2500 = +25%).
pub fn refund_fee(rate: &FeeRate, margin_bps: u64) -> u64 {
    let base = estimate_fee(rate, sweep_weight(), Priority::High);
    let bumped = base.saturating_add(base.saturating_mul(margin_bps) / 10_000);
    quantize_up(bumped, rate.quantization_mask)
}

/// Recommended refund margin (basis points): +50%. Refunds are rare and the
/// overpay is a few cents of insurance against a fee spike stranding funds.
pub const REFUND_MARGIN_BPS: u64 = 5_000;

/// The spendable output amount after deducting `fee` from a joint input of
/// `input_amount`. Returns `None` if the fee would meet or exceed the input
/// (the transaction would have nothing to send) — the caller MUST NOT sign in
/// that case. This is the single guard that keeps a swap from producing an
/// invalid or zero-value settlement.
pub fn net_output_after_fee(input_amount: u64, fee: u64) -> Option<u64> {
    match input_amount.checked_sub(fee) {
        Some(0) | None => None,
        Some(net) => Some(net),
    }
}

/// Whether an input of `input_amount` can cover the sweep fee at `priority`
/// and still leave a non-zero output. A maker uses this to refuse dust-sized
/// chunks that a fee would entirely consume.
pub fn covers_fee(rate: &FeeRate, input_amount: u64, priority: Priority) -> bool {
    net_output_after_fee(input_amount, sweep_fee(rate, priority)).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantization_rounds_up_to_the_mask() {
        assert_eq!(quantize_up(0, 1_000), 0);
        assert_eq!(quantize_up(1, 1_000), 1_000);
        assert_eq!(quantize_up(1_000, 1_000), 1_000);
        assert_eq!(quantize_up(1_001, 1_000), 2_000);
        // A zero mask must not divide-by-zero; treated as 1.
        assert_eq!(quantize_up(7, 0), 7);
    }

    #[test]
    fn weight_is_monotonic_and_in_a_sane_range() {
        // A 1-in/2-out ring-16 tx is ~1.4–2.0 KB; our estimate is a slight
        // over-estimate in that band.
        let w = sweep_weight();
        assert!((1_400..=2_200).contains(&w), "sweep weight {w} out of band");
        // More inputs and outputs strictly increase weight.
        assert!(tx_weight(2, 2) > tx_weight(1, 2));
        assert!(tx_weight(1, 3) > tx_weight(1, 2));
    }

    #[test]
    fn priority_tiers_are_ordered_and_quantized() {
        let r = FeeRate::FALLBACK;
        let w = sweep_weight();
        let lo = estimate_fee(&r, w, Priority::Low);
        let no = estimate_fee(&r, w, Priority::Normal);
        let hi = estimate_fee(&r, w, Priority::High);
        assert!(lo < no && no < hi, "tiers not ordered: {lo} {no} {hi}");
        // Every fee is a multiple of the quantization mask.
        for f in [lo, no, hi] {
            assert_eq!(f % r.quantization_mask, 0);
        }
    }

    #[test]
    fn net_of_fee_refuses_underflow_and_zero() {
        assert_eq!(net_output_after_fee(1_000, 400), Some(600));
        assert_eq!(net_output_after_fee(400, 400), None); // nothing left to send
        assert_eq!(net_output_after_fee(399, 400), None); // underflow
        assert_eq!(net_output_after_fee(0, 0), None);
    }

    #[test]
    fn refund_fee_overpays_the_high_tier() {
        let r = FeeRate::FALLBACK;
        let plain_high = estimate_fee(&r, sweep_weight(), Priority::High);
        let refund = refund_fee(&r, REFUND_MARGIN_BPS);
        assert!(refund > plain_high, "refund {refund} must exceed high {plain_high}");
        assert_eq!(refund % r.quantization_mask, 0);
    }

    #[test]
    fn covers_fee_rejects_dust() {
        let r = FeeRate::FALLBACK;
        let fee = sweep_fee(&r, Priority::Normal);
        assert!(covers_fee(&r, fee + 1, Priority::Normal));
        assert!(!covers_fee(&r, fee, Priority::Normal));
        assert!(!covers_fee(&r, fee - 1, Priority::Normal));
    }
}
