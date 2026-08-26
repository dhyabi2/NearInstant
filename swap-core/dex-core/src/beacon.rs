//! The Nano-block order beacon (R4) — a serverless, censorship-resistant
//! order-discovery channel that lives on the Nano ledger itself.
//!
//! Nano blocks are FREE and instant, which makes Nano — uniquely among
//! chains — usable as a bulletin board: publishing an order intent costs one
//! dust send. The scheme:
//!
//! - A **namespace account** is derived deterministically from the market and
//!   side (`Blake2b-256("xnoxmr-beacon-v1" ‖ pair ‖ side)` as the account
//!   public key). Nobody holds its private key; dust sent there is burned —
//!   the send block IS the message. Every watcher derives the same account
//!   and polls its receivable entries: no relay, no server, nothing to take
//!   down or censor.
//!
//! - The **payload rides in the send's amount**: a raw amount is 128 bits,
//!   and a dust ceiling still leaves 64 usable bits. We encode
//!   `version ‖ side ‖ price ‖ size-bucket ‖ checksum` into the low 64 bits.
//!   The sender's account (visible on the receivable entry) is the maker's
//!   trading identity; the block's timestamp/ordering comes from the ledger.
//!
//! - Cost ceiling: the encoded amount is < 2^64 raw ≈ 1.8e-11 XNO — twelve
//!   orders of magnitude below one XNO. Spam costs the spammer PoW per block
//!   (Nano's own anti-spam), not the watchers.
//!
//! This module is the codec + namespace derivation (transport-agnostic, fully
//! tested). Publishing = a normal Nano send of `encode(...)` raw to
//! `namespace_account(...)`; scanning = the `receivable` RPC on that account.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use crate::order::Side;

/// 32-byte account/public-key alias (matches the workspace convention).
pub type Bytes32 = [u8; 32];

/// Codec version.
const VERSION: u8 = 1;
/// Domain-separation prefix for namespace accounts.
const NS_PREFIX: &[u8] = b"xnoxmr-beacon-v1";

/// A compact order intent: enough for discovery (who, which side, roughly
/// what price and size); the full signed order is exchanged after contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Intent {
    pub side: Side,
    /// Price in nano-XMR per XNO (piconero·10⁻³ per raw-XNO·10³⁰ — i.e.
    /// XMR/XNO × 1e9), capped at 2^40−1 (≈ 1099 XMR per XNO, far above any
    /// plausible rate).
    pub price_e9: u64,
    /// Size bucket: order magnitude of the offered size, `floor(log2(raw))`,
    /// 0–255. Coarse on purpose — exact size is negotiated off-beacon.
    pub size_log2: u8,
}

/// The deterministic burn account for a market side. Everyone derives the
/// same account; watchers poll its receivable entries.
pub fn namespace_account(pair: &str, side: Side) -> Bytes32 {
    let mut h = Blake2b::<U32>::new();
    h.update(NS_PREFIX);
    h.update([0x00]);
    h.update(pair.as_bytes());
    h.update([0x00]);
    h.update([side_code(side)]);
    h.finalize().into()
}

fn side_code(s: Side) -> u8 {
    match s {
        Side::SellXno => 0,
        Side::SellXmr => 1,
    }
}

fn side_of(code: u8) -> Option<Side> {
    match code {
        0 => Some(Side::SellXno),
        1 => Some(Side::SellXmr),
        _ => None,
    }
}

/// Layout of the low 64 bits of the amount (high 64 bits must be zero):
///
/// ```text
/// bits 60..63  version (4 bits)
/// bit  59      side (1 bit)
/// bits 19..58  price_e9 (40 bits)
/// bits 11..18  size_log2 (8 bits)
/// bits  0..10  checksum (11 bits, Blake2b over the payload)
/// ```
const PRICE_BITS: u32 = 40;
const CHECK_BITS: u32 = 11;

fn checksum(body: u64) -> u64 {
    let mut h = Blake2b::<U32>::new();
    h.update(b"beacon-check");
    h.update(body.to_le_bytes());
    let d: Bytes32 = h.finalize().into();
    (u64::from_le_bytes(d[..8].try_into().unwrap())) & ((1 << CHECK_BITS) - 1)
}

/// Encode an intent into the raw amount of the beacon send. `None` if the
/// price overflows its 40-bit field.
pub fn encode(intent: &Intent) -> Option<u128> {
    if intent.price_e9 >= 1 << PRICE_BITS {
        return None;
    }
    let body: u64 = ((VERSION as u64) << 60)
        | ((side_code(intent.side) as u64) << 59)
        | (intent.price_e9 << 19)
        | ((intent.size_log2 as u64) << 11);
    Some((body | checksum(body)) as u128)
}

/// Decode a receivable amount back into an intent. `None` for amounts that
/// are not beacon-encoded (wrong version, bad checksum, high bits set) — so a
/// watcher can safely scan a namespace account that also receives junk.
pub fn decode(amount: u128) -> Option<Intent> {
    if amount >> 64 != 0 {
        return None;
    }
    let word = amount as u64;
    let body = word & !((1 << CHECK_BITS) - 1);
    if word & ((1 << CHECK_BITS) - 1) != checksum(body) {
        return None;
    }
    if (body >> 60) as u8 != VERSION {
        return None;
    }
    let side = side_of(((body >> 59) & 1) as u8)?;
    Some(Intent {
        side,
        price_e9: (body >> 19) & ((1 << PRICE_BITS) - 1),
        size_log2: ((body >> 11) & 0xFF) as u8,
    })
}

/// A decoded order intent found on a namespace account: who posted it (the
/// sender of the beacon block), the intent, and the block hash carrying it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostedIntent {
    /// The maker's account (the beacon block's sender) — their trading
    /// identity and where a taker opens contact.
    pub maker: Bytes32,
    pub intent: Intent,
    /// The beacon block's hash (ledger-unique; used to de-duplicate).
    pub block_hash: Bytes32,
}

/// The minimal ledger surface the beacon needs — implemented over a real Nano
/// RPC node (receivable + send) or a mock. Kept in `dex-core` as a trait so
/// the orchestration below is transport-agnostic and unit-testable.
pub trait BeaconLedger {
    /// Receivable sends sitting on `account`: `(sender, amount_raw, block_hash)`.
    fn receivables(&self, account: &Bytes32) -> Result<Vec<(Bytes32, u128, Bytes32)>, String>;
    /// Send `amount` raw from `from_key`'s account to `to`; returns the send
    /// block hash. `from_key` is a 32-byte Nano seed/private key.
    fn send(&self, from_key: &Bytes32, to: &Bytes32, amount: u128) -> Result<Bytes32, String>;
}

/// Publish an order intent to the beacon: send its encoded dust amount to the
/// market-side namespace account. Returns the beacon block hash.
pub fn publish(
    ledger: &dyn BeaconLedger,
    from_key: &Bytes32,
    pair: &str,
    intent: &Intent,
) -> Result<Bytes32, String> {
    let amount = encode(intent).ok_or("intent price out of range")?;
    let account = namespace_account(pair, intent.side);
    ledger.send(from_key, &account, amount)
}

/// Scan a market side's namespace account for live order intents. Non-beacon
/// receivables (junk dust, wrong version, bad checksum) are silently skipped,
/// so the account can safely receive noise. Results are de-duplicated by
/// block hash and returned newest-first as the ledger reports them.
pub fn scan(
    ledger: &dyn BeaconLedger,
    pair: &str,
    side: Side,
) -> Result<Vec<PostedIntent>, String> {
    let account = namespace_account(pair, side);
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for (maker, amount, block_hash) in ledger.receivables(&account)? {
        if !seen.insert(block_hash) {
            continue;
        }
        if let Some(intent) = decode(amount) {
            // The namespace encodes the side; ignore anything mis-sent to the
            // wrong side's account (defends against a spammer crossing sides).
            if intent.side == side {
                out.push(PostedIntent { maker, intent, block_hash });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// In-memory ledger: `send` records a receivable on the destination.
    #[derive(Default)]
    struct MockLedger {
        // account -> Vec<(sender, amount, block_hash)>
        receivable: RefCell<std::collections::HashMap<Bytes32, Vec<(Bytes32, u128, Bytes32)>>>,
        next_hash: RefCell<u8>,
    }
    impl BeaconLedger for MockLedger {
        fn receivables(&self, account: &Bytes32) -> Result<Vec<(Bytes32, u128, Bytes32)>, String> {
            Ok(self.receivable.borrow().get(account).cloned().unwrap_or_default())
        }
        fn send(&self, from_key: &Bytes32, to: &Bytes32, amount: u128) -> Result<Bytes32, String> {
            let mut h = *self.next_hash.borrow();
            h += 1;
            *self.next_hash.borrow_mut() = h;
            let sender = [from_key[0]; 32]; // stand-in "account" from the key
            self.receivable
                .borrow_mut()
                .entry(*to)
                .or_default()
                .push((sender, amount, [h; 32]));
            Ok([h; 32])
        }
    }

    #[test]
    fn publish_then_scan_round_trips_an_intent() {
        let ledger = MockLedger::default();
        let maker_key = [0x7A; 32];
        let intent = Intent { side: Side::SellXmr, price_e9: 3_750_000, size_log2: 100 };
        publish(&ledger, &maker_key, "XNO/XMR", &intent).unwrap();

        let found = scan(&ledger, "XNO/XMR", Side::SellXmr).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].intent, intent);
        assert_eq!(found[0].maker, [0x7A; 32]);

        // The opposite side's account is empty.
        assert!(scan(&ledger, "XNO/XMR", Side::SellXno).unwrap().is_empty());
    }

    #[test]
    fn scan_skips_junk_and_dedups() {
        let ledger = MockLedger::default();
        let account = namespace_account("XNO/XMR", Side::SellXno);
        let good = encode(&Intent { side: Side::SellXno, price_e9: 42, size_log2: 7 }).unwrap();
        {
            let mut r = ledger.receivable.borrow_mut();
            let v = r.entry(account).or_default();
            v.push(([1; 32], good, [10; 32]));        // valid
            v.push(([2; 32], 1_000_000, [11; 32]));   // ordinary dust — not beacon
            v.push(([3; 32], good ^ 1, [12; 32]));    // checksum flip
            v.push(([1; 32], good, [10; 32]));        // duplicate hash
        }
        let found = scan(&ledger, "XNO/XMR", Side::SellXno).unwrap();
        assert_eq!(found.len(), 1, "only the one valid, de-duplicated intent survives");
        assert_eq!(found[0].block_hash, [10; 32]);
    }

    #[test]
    fn round_trips_exactly() {
        for (side, price, size) in [
            (Side::SellXno, 0u64, 0u8),
            (Side::SellXmr, 3_750_000, 100),          // 0.00375 XMR/XNO, ~2^100 raw
            (Side::SellXno, (1 << PRICE_BITS) - 1, 255),
        ] {
            let i = Intent { side, price_e9: price, size_log2: size };
            let amount = encode(&i).expect("encodes");
            assert_eq!(decode(amount), Some(i), "round trip {i:?}");
            // Dust by construction: less than 2^64 raw (~1.8e-11 XNO).
            assert!(amount < 1 << 64);
        }
    }

    #[test]
    fn price_overflow_refused() {
        let i = Intent { side: Side::SellXno, price_e9: 1 << PRICE_BITS, size_log2: 0 };
        assert_eq!(encode(&i), None);
    }

    #[test]
    fn junk_amounts_rejected() {
        assert_eq!(decode(0), None, "zero fails the checksum");
        assert_eq!(decode(1u128 << 100), None, "high bits set");
        let good = encode(&Intent { side: Side::SellXmr, price_e9: 42, size_log2: 7 }).unwrap();
        assert_eq!(decode(good ^ 1), None, "checksum-bit flip rejected");
        assert_eq!(decode(good ^ (1 << 30)), None, "payload-bit flip rejected");
        // A plausible ordinary dust payment (round number) is not misread.
        assert_eq!(decode(1_000_000), None);
    }

    #[test]
    fn namespace_is_deterministic_and_separated() {
        let a = namespace_account("XNO/XMR", Side::SellXno);
        assert_eq!(a, namespace_account("XNO/XMR", Side::SellXno), "deterministic");
        assert_ne!(a, namespace_account("XNO/XMR", Side::SellXmr), "sides separated");
        assert_ne!(a, namespace_account("XNO/BTC", Side::SellXno), "pairs separated");
    }
}
