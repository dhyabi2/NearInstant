//! Block 7 battery: every DEX layer exercised — order signing, book
//! determinism + Merkle anchoring, journal-only market data, commit-reveal
//! matching with FCFS audit, local triggers, the earn engine's risk
//! controls, the deterministic ledger, and the privacy planner.

use rand::rngs::OsRng;

use dex_core::book::{merkle_root, verify_inclusion, Book};
use dex_core::earn::{quote, realized_band, Breaker, Inventory, Limits, Quotes};
use dex_core::ledger::{replay, Event as LEvent};
use dex_core::market::{candles, ticker, SettledTrade};
use dex_core::matching::{
    audit_fcfs, commit, receipt_message, select_for_amount, verify_reveal, Receipt,
    TicketRegistry,
};
use dex_core::order::{OrderBody, Side, SignedOrder, MAX_ORDER_TTL_SECS};
use dex_core::privacy::{assign_hops, denominate, plan, round_trip_cost, PlanError};
use dex_core::triggers::{Action, Condition, Engine, Trigger};

// ---------------------------------------------------------------- helpers

struct Maker {
    key: frost_core::SigningKey<signing::Ed25519Blake2b>,
    pubkey: [u8; 32],
}

fn maker() -> Maker {
    let key = frost_core::SigningKey::<signing::Ed25519Blake2b>::new(&mut OsRng);
    let vk = frost_core::VerifyingKey::from(&key);
    Maker {
        key,
        pubkey: vk.serialize().unwrap().try_into().unwrap(),
    }
}

fn sign_order(m: &Maker, body: OrderBody) -> SignedOrder {
    let sig = m.key.sign(&mut OsRng, &body.encode());
    SignedOrder {
        body,
        signature: sig.serialize().unwrap().try_into().unwrap(),
    }
}

fn body(m: &Maker, side: Side, amount: u128, rate: u128, nonce: u64) -> OrderBody {
    OrderBody {
        maker: m.pubkey,
        side,
        amount,
        rate_pico: rate,
        expiry: 10_000,
        nonce,
        pof_hash: [0xEE; 32],
    }
}

// ---------------------------------------------------------------- orders

#[test]
fn orders_sign_verify_and_reject_tampering() {
    let m = maker();
    let o = sign_order(&m, body(&m, Side::SellXno, 500, 3_750_000_000, 1));
    assert!(o.verify(100));
    // Expired: refused.
    assert!(!o.verify(10_000));
    // Tampered amount: refused.
    let mut bad = o.clone();
    bad.body.amount = 501;
    assert!(!bad.verify(100));
    // Foreign signature: refused.
    let other = maker();
    let mut forged = o.clone();
    forged.body.maker = other.pubkey;
    assert!(!forged.verify(100));
}

#[test]
fn orders_reject_unbounded_future_expiry() {
    let m = maker();
    // A correctly-signed order whose expiry exceeds the max TTL is refused: it
    // would otherwise squat in the book until the relay's capacity is spent.
    let far = OrderBody {
        expiry: 100 + MAX_ORDER_TTL_SECS + 1,
        ..body(&m, Side::SellXno, 500, 3_750_000_000, 1)
    };
    assert!(!sign_order(&m, far).verify(100));

    // Exactly at the bound is accepted.
    let bound = OrderBody {
        expiry: 100 + MAX_ORDER_TTL_SECS,
        ..body(&m, Side::SellXno, 500, 3_750_000_000, 2)
    };
    assert!(sign_order(&m, bound).verify(100));
}

// ---------------------------------------------------------------- book

#[test]
fn book_is_deterministic_and_merkle_anchored() {
    let m1 = maker();
    let m2 = maker();
    let orders = vec![
        sign_order(&m1, body(&m1, Side::SellXno, 100, 3_700_000_000, 1)),
        sign_order(&m2, body(&m2, Side::SellXno, 250, 3_700_000_000, 2)),
        sign_order(&m1, body(&m1, Side::SellXno, 400, 3_800_000_000, 3)),
        sign_order(&m2, body(&m2, Side::SellXmr, 900, 3_600_000_000, 4)),
    ];

    // Two clients ingest in different orders (one with PoF flags differing
    // only in metadata order): identical roots and ladders.
    let mut a = Book::default();
    let mut b = Book::default();
    for o in &orders {
        assert!(a.insert(o.clone(), 100, true));
    }
    for o in orders.iter().rev() {
        assert!(b.insert(o.clone(), 100, true));
    }
    assert_eq!(a.merkle_root(), b.merkle_root());
    assert_eq!(a.levels(Side::SellXno, 100), b.levels(Side::SellXno, 100));

    // Best-priced first: SellXno ladder starts at the LOW rate.
    let ladder = a.levels(Side::SellXno, 100);
    assert_eq!(ladder[0].rate_pico, 3_700_000_000);
    assert_eq!(ladder[0].verified_amount, 350);

    // Unverified PoF is flagged depth, not hidden.
    let m3 = maker();
    let o5 = sign_order(&m3, body(&m3, Side::SellXno, 50, 3_700_000_000, 5));
    a.insert(o5.clone(), 100, false);
    let ladder = a.levels(Side::SellXno, 100);
    assert_eq!(ladder[0].verified_amount, 350);
    assert_eq!(ladder[0].unverified_amount, 50);

    // Inclusion proof verifies against the root; tampered leaf fails.
    let root = a.merkle_root();
    let leaf = o5.body.hash();
    let path = a.inclusion_proof(&leaf).unwrap();
    assert!(verify_inclusion(&leaf, &path, &root));
    assert!(!verify_inclusion(&[9u8; 32], &path, &root));

    // Expiry sweep removes dead orders and changes the root.
    let mut c = Book::default();
    let m4 = maker();
    let mut dying = body(&m4, Side::SellXno, 10, 1_000, 9);
    dying.expiry = 200;
    c.insert(sign_order(&m4, dying), 100, true);
    assert_eq!(c.len(), 1);
    assert_eq!(c.sweep_expired(300).len(), 1);
    assert!(c.is_empty());
    assert_eq!(c.merkle_root(), merkle_root(&[]));
}

#[test]
fn book_mid_is_a_quote_not_settled_data() {
    // The reference mid is derived from the live book's best bid/ask, and is
    // `None` when either side has no depth — never a fabricated number.
    assert_eq!(Book::default().mid(), None);

    let m = maker();
    let mut book = Book::default();
    // Ask: sell XNO at 0.003800; bid: sell XMR at 0.003600 → mid 0.003700.
    book.insert(sign_order(&m, body(&m, Side::SellXno, 100, 3_800_000_000, 1)), 100, true);
    book.insert(sign_order(&m, body(&m, Side::SellXmr, 100, 3_600_000_000, 2)), 100, true);
    let mid = book.mid().expect("two-sided book has a mid");
    assert!((mid - 0.003700).abs() < 1e-12, "mid {mid}");

    // One-sided book still quotes from the single resting side.
    let mut ask_only = Book::default();
    ask_only.insert(sign_order(&m, body(&m, Side::SellXno, 100, 3_800_000_000, 1)), 100, true);
    assert!((ask_only.mid().unwrap() - 0.003800).abs() < 1e-12);
}

// ---------------------------------------------------------------- market

#[test]
fn candles_and_ticker_come_from_settled_trades_only() {
    let trades = vec![
        SettledTrade { price: 100.0, size: 5.0, timestamp: 30 },
        SettledTrade { price: 105.0, size: 2.0, timestamp: 55 },
        SettledTrade { price: 95.0, size: 1.0, timestamp: 70 },
        SettledTrade { price: 99.0, size: 4.0, timestamp: 110 },
    ];
    let cs = candles(&trades, 60);
    assert_eq!(cs.len(), 2);
    assert_eq!((cs[0].open, cs[0].high, cs[0].low, cs[0].close), (100.0, 105.0, 100.0, 105.0));
    assert_eq!(cs[0].volume, 7.0);
    assert_eq!(cs[1].trade_count, 2);

    // Integrity hash pins the constituent trades: a shifted price changes it.
    let mut tampered = trades.clone();
    tampered[0].price = 101.0;
    assert_ne!(candles(&tampered, 60)[0].integrity, cs[0].integrity);

    let t = ticker(&trades, 120, 60.0, 60);
    assert_eq!(t.last, Some(99.0));
    assert_eq!(t.volume, 5.0); // only trades within the window
    assert!(t.vwap.is_some());

    // Empty market shown empty.
    assert_eq!(ticker(&[], 0, 60.0, 60).vwap, None);

    // A zero interval is a caller bug; it returns empty rather than panicking.
    assert!(candles(&trades, 0).is_empty());
}

// ---------------------------------------------------------------- matching

#[test]
fn matching_commit_reveal_tickets_and_fcfs_audit() {
    let m1 = maker();
    let m2 = maker();
    let mut book = Book::default();
    let o_cheap = sign_order(&m1, body(&m1, Side::SellXno, 300, 3_700_000_000, 1));
    let o_dear = sign_order(&m2, body(&m2, Side::SellXno, 300, 3_900_000_000, 2));
    book.insert(o_cheap.clone(), 10, true);
    book.insert(o_dear.clone(), 10, true);

    // Best execution walks the cheap order first, spills into the dear one.
    // A third-party taker (not either maker) sees both levels.
    let picks = select_for_amount(&book, Side::SellXno, 450, &[0x77; 32]);
    assert_eq!(picks.len(), 2);
    assert_eq!(picks[0].0.order.body.hash(), o_cheap.body.hash());
    assert_eq!(picks[0].1, 300);
    assert_eq!(picks[1].1, 150);

    // Commit-reveal: the reveal must match the prior commitment.
    let taker = [0x77; 32];
    let salt = [0x42; 32];
    let cm = commit(&o_cheap.body.hash(), &taker, &salt);
    assert!(verify_reveal(&cm, &o_cheap.body.hash(), &taker, &salt));
    assert!(!verify_reveal(&cm, &o_dear.body.hash(), &taker, &salt));
    assert!(!verify_reveal(&cm, &o_cheap.body.hash(), &taker, &[0x43; 32]));

    // Single-use tickets: exactly one taker consumes a quote.
    let mut reg = TicketRegistry::default();
    assert!(reg.consume(&o_cheap.body.hash()));
    assert!(!reg.consume(&o_cheap.body.hash()));

    // FCFS receipts: maker signs arrival order; settling out of order is
    // provable from public data.
    let mk = maker();
    let receipts: Vec<Receipt> = [(o_cheap.body.hash(), 1u64), (o_dear.body.hash(), 2u64)]
        .iter()
        .map(|(oh, seq)| {
            let sig = mk.key.sign(&mut OsRng, &receipt_message(oh, &taker, *seq));
            Receipt {
                order_hash: *oh,
                taker,
                seq: *seq,
                maker: mk.pubkey,
                signature: sig.serialize().unwrap().try_into().unwrap(),
            }
        })
        .collect();
    assert!(receipts.iter().all(|r| r.verify()));
    // In-order settlement: clean audit.
    assert_eq!(
        audit_fcfs(&receipts, &[o_cheap.body.hash(), o_dear.body.hash()]),
        None
    );
    // Reordered settlement: convicted with the skipped sequence as evidence.
    assert_eq!(
        audit_fcfs(&receipts, &[o_dear.body.hash(), o_cheap.body.hash()]),
        Some((2, 1))
    );
}

// ---------------------------------------------------------------- triggers

#[test]
fn triggers_fire_locally_with_oco_exclusivity() {
    let mut e = Engine::default();
    // OCO bracket: take-profit at 110, stop-loss at 90.
    e.arm(Trigger::new(1, Condition::StopAbove { level: 110.0 }, Action::FireMarket, 1_000, Some(7)));
    e.arm(Trigger::new(2, Condition::StopBelow { level: 90.0 }, Action::FireMarket, 1_000, Some(7)));
    // Independent trailing stop, 5 below the high-water mark.
    e.arm(Trigger::new(3, Condition::Trailing { distance: 5.0 }, Action::FireLimit { rate: 0.0 }, 1_000, None));

    assert!(e.step(100.0, 10).is_none()); // nothing crossed; watermark=100
    assert!(e.step(104.0, 11).is_none()); // watermark=104
    // Price collapses to 89: stop-loss (id 2) fires; its OCO twin cancels;
    // the trailing stop (104-5=99 ≥ 89) ALSO wants to fire but only one
    // trigger fires per step — deterministic lowest-id-first among crossed.
    let fired = e.step(89.0, 12).unwrap();
    assert_eq!(fired.id, 2);
    // The OCO twin (take-profit, id 1) is cancelled atomically with the fire.
    assert_eq!(fired.cancelled, vec![1]);
    assert_eq!(e.armed(), 1); // only the trailing stop remains
    let fired2 = e.step(89.0, 13).unwrap();
    assert_eq!(fired2.id, 3);
    assert_eq!(e.armed(), 0);

    // Expiry drops triggers without firing.
    let mut e2 = Engine::default();
    e2.arm(Trigger::new(9, Condition::StopBelow { level: 90.0 }, Action::FireMarket, 5, None));
    assert!(e2.step(50.0, 10).is_none());
    assert_eq!(e2.armed(), 0);
}

// ---------------------------------------------------------------- earn

#[test]
fn earn_engine_risk_controls() {
    let limits = Limits {
        half_spread: 0.002,
        vol_widening: 1.0,
        max_skew: 0.3,
        skew_lean: 0.01,
        max_drawdown: 0.05,
        vol_pull: 0.05,
    };
    let balanced = Inventory { xno_value: 50.0, xmr_value: 50.0 };
    let breaker = Breaker::new(100.0);

    // Calm, balanced: two-sided quotes around the VWAP.
    match quote(0.00375, 0.004, &balanced, &limits, &breaker) {
        Quotes::TwoSided { bid, ask } => {
            assert!(bid < 0.00375 && ask > 0.00375);
        }
        q => panic!("expected two-sided, got {q:?}"),
    }

    // XNO-heavy beyond max_skew: only the shedding side quotes.
    let heavy = Inventory { xno_value: 90.0, xmr_value: 10.0 };
    assert!(matches!(
        quote(0.00375, 0.004, &heavy, &limits, &breaker),
        Quotes::Skewed { bid: None, ask: Some(_) }
    ));

    // Volatility spike: pulled.
    assert!(matches!(
        quote(0.00375, 0.10, &balanced, &limits, &breaker),
        Quotes::Pulled("volatility spike")
    ));

    // Drawdown breaker latches and stays tripped even after recovery.
    let mut br = Breaker::new(100.0);
    assert!(!br.update(97.0, limits.max_drawdown));
    assert!(br.update(94.0, limits.max_drawdown));
    assert!(br.update(100.0, limits.max_drawdown), "breaker latches");
    assert!(matches!(
        quote(0.00375, 0.004, &balanced, &limits, &br),
        Quotes::Pulled("drawdown breaker")
    ));

    // Realized band: no history ⇒ None (never a fabricated projection).
    assert_eq!(realized_band(&[], 100.0, 1_000, 3_600), None);
    let fills: Vec<(u64, f64)> = (0..10).map(|i| (900 + i * 10, 0.05)).collect();
    let (lo, hi) = realized_band(&fills, 100.0, 1_000, 3_600).unwrap();
    assert!(lo >= 0.0 && hi >= lo);
}

// ---------------------------------------------------------------- ledger

#[test]
fn ledger_replay_is_deterministic_and_honest() {
    let events = vec![
        LEvent::BondLock { t: 0, amount_xmr: 10.0 },
        LEvent::Fill { t: 100, strategy: 1, spread_xmr: 0.5 },
        LEvent::Fill { t: 150, strategy: 2, spread_xmr: 0.3 },
        LEvent::Premium { t: 200, strategy: 1, amount_xmr: 0.4, duration: 400 },
        LEvent::Service { t: 250, service: 1, amount_xmr: 0.2 },
        LEvent::Cost { t: 260, amount_xmr: 0.1 },
        LEvent::InventoryDelta { t: 300, xno: 1_000.0, xmr: -3.75 },
    ];
    let s = replay(&events, 400, 0.00375, 0.000001);

    // Premium accrues along its decay: at t=400, 200/400 elapsed ⇒ half.
    assert!((s.premium_recognized - 0.2).abs() < 1e-12);
    assert!((s.premium_deferred - 0.2).abs() < 1e-12);
    // Costs and bond opportunity cost are netted.
    assert!((s.costs - 0.1).abs() < 1e-12);
    assert!((s.bond_opportunity_cost - 10.0 * 0.000001 * 400.0).abs() < 1e-12);
    // Strategy attribution: fills + accrued premium per tag.
    let by: std::collections::BTreeMap<u32, f64> = s.by_strategy.iter().cloned().collect();
    assert!((by[&1] - 0.7).abs() < 1e-12);
    assert!((by[&2] - 0.3).abs() < 1e-12);
    // Mark-to-VWAP unrealized.
    assert!((s.unrealized_xmr_eq - 3.75).abs() < 1e-12);
    // Determinism: same inputs, identical statement.
    assert_eq!(s, replay(&events, 400, 0.00375, 0.000001));
    // Full accrual once the duration passes.
    let s2 = replay(&events, 1_000, 0.00375, 0.000001);
    assert!((s2.premium_recognized - 0.4).abs() < 1e-12);
    assert!(s2.premium_deferred.abs() < 1e-12);
}

// ---------------------------------------------------------------- privacy

#[test]
fn privacy_planner_denominates_windows_and_costs() {
    let one = 1_000_000_000_000_000_000_000_000_000_000u128; // 1 XNO
    // 143.1 XNO → 100+30+10+3+0.1, change 0.
    let amount = 143 * one + one / 10;
    let (denoms, change) = denominate(amount);
    assert_eq!(denoms.len(), 5);
    assert_eq!(change, 0);
    assert_eq!(denoms.iter().sum::<u128>(), amount);

    // Sub-denomination dust stays home as change.
    let (d2, c2) = denominate(one / 100);
    assert!(d2.is_empty());
    assert_eq!(c2, one / 100);
    assert_eq!(plan(one / 100, 5, 0, 4), Err(PlanError::TooSmall));

    // Legs spread across batch windows; hops use distinct counterparties.
    let p = plan(amount, 4, 10, 3).unwrap();
    assert_eq!(p.legs.len(), 5);
    assert!(p.legs.iter().all(|l| (10..13).contains(&l.window)));
    for i in 0..p.legs.len() {
        let (a, b) = assign_hops(i, 4);
        assert_ne!(a, b);
    }
    // Not enough peers: refused, with the honest numbers.
    assert_eq!(
        plan(amount, 1, 0, 3),
        Err(PlanError::NotEnoughCounterparties { need: 2, have: 1 })
    );

    // The honesty line: two spreads + two premiums.
    assert!((round_trip_cost(0.002, 0.004) - 0.012).abs() < 1e-12);
}

#[test]
fn audit_fcfs_flags_settlement_with_no_receipt() {
    // Audit #8: a maker that settles a taker for whom it issued NO receipt is
    // a reordering violation, not a clean audit.
    let mk = maker();
    let taker = [0x77u8; 32];
    let o1 = sign_order(&mk, body(&mk, Side::SellXno, 100, 3_700_000_000, 1));
    let o2 = sign_order(&mk, body(&mk, Side::SellXno, 100, 3_700_000_000, 2));
    // only o1 has a receipt
    let sig = mk.key.sign(&mut OsRng, &receipt_message(&o1.body.hash(), &taker, 1));
    let receipts = vec![Receipt {
        order_hash: o1.body.hash(), taker, seq: 1, maker: mk.pubkey,
        signature: sig.serialize().unwrap().try_into().unwrap(),
    }];
    // settling o2 (no receipt) must be flagged, not None
    assert!(audit_fcfs(&receipts, &[o2.body.hash()]).is_some());
    // settling o1 (its receipt is lowest) is clean
    assert_eq!(audit_fcfs(&receipts, &[o1.body.hash()]), None);
}

/// Audit (self-match / wash-trading): a taker cannot select its own resting
/// orders. Allowing it would let one party manufacture settled trades — the
/// sole feed for the ticker/VWAP, earn engine and triggers.
#[test]
fn taker_cannot_self_match_its_own_orders() {
    use dex_core::matching::is_self_match;
    let m = maker();
    let mut book = Book::default();
    let mine = sign_order(&m, body(&m, Side::SellXno, 300, 3_700_000_000, 1));
    book.insert(mine.clone(), 10, true);

    // The maker itself gets NOTHING from the book (its own order is skipped).
    let picks_self = select_for_amount(&book, Side::SellXno, 300, &m.pubkey);
    assert!(picks_self.is_empty(), "self-match must yield no picks");
    assert!(is_self_match(&book.side(Side::SellXno)[0], &m.pubkey));

    // A different taker still matches it normally.
    let picks_other = select_for_amount(&book, Side::SellXno, 300, &[0x55; 32]);
    assert_eq!(picks_other.len(), 1);
    assert!(!is_self_match(&book.side(Side::SellXno)[0], &[0x55; 32]));
}

/// Audit (FCFS-determinism): the verdict must not depend on the receipt
/// vector's order, and duplicate arrival sequences are themselves a violation.
#[test]
fn fcfs_audit_is_order_independent_and_rejects_duplicate_seq() {
    let mk = maker();
    let taker = [0x77; 32];
    let a = [0xA0; 32];
    let b = [0xB0; 32];
    let mkr = |oh: [u8; 32], seq: u64| {
        let sig = mk.key.sign(&mut OsRng, &receipt_message(&oh, &taker, seq));
        Receipt { order_hash: oh, taker, seq, maker: mk.pubkey,
            signature: sig.serialize().unwrap().try_into().unwrap() }
    };
    // Two receipts BOTH claiming seq=1 ("you were first" told twice) — a
    // provable violation regardless of settlement or receipt order.
    let dup = vec![mkr(a, 1), mkr(b, 1)];
    let v1 = audit_fcfs(&dup, &[a, b]);
    let v2 = audit_fcfs(&vec![mkr(b, 1), mkr(a, 1)], &[b, a]);
    assert!(v1.is_some(), "duplicate seq must convict");
    assert_eq!(v1, v2, "verdict must be independent of receipt/settlement order");
    assert_eq!(v1, Some((1, 1)));
}

/// E2E: the LIMIT vs MARKET order lifecycle end to end.
/// A limit order is a signed order that rests in the book at its price; a
/// market order is a taker walking that depth best-first (select_for_amount).
/// Exercises: limit resting + price ladder, market sweep across multiple
/// levels with best-execution blended price, partial fill beyond available
/// depth, zero fill on an empty book (no phantom fill), and side-direction.
#[test]
fn limit_and_market_order_lifecycle() {
    let m = maker();
    let taker = [0x77u8; 32]; // distinct from the maker → not a self-match
    let mut book = Book::default();

    // --- LIMIT orders rest at three price levels (best = lowest rate). ---
    book.insert(sign_order(&m, body(&m, Side::SellXno, 100, 3_700_000_000, 1)), 10, true);
    book.insert(sign_order(&m, body(&m, Side::SellXno, 200, 3_750_000_000, 2)), 10, true);
    book.insert(sign_order(&m, body(&m, Side::SellXno, 300, 3_800_000_000, 3)), 10, true);

    let ladder = book.levels(Side::SellXno, 10);
    assert_eq!(ladder.len(), 3, "three resting limit levels");
    assert_eq!(ladder[0].rate_pico, 3_700_000_000, "best (lowest) rate first");
    assert_eq!(ladder[0].verified_amount, 100);
    assert!(ladder[0].rate_pico < ladder[1].rate_pico && ladder[1].rate_pico < ladder[2].rate_pico);

    // --- MARKET buy 250: fills best level fully (100), spills partial (150). ---
    let picks = select_for_amount(&book, Side::SellXno, 250, &taker);
    assert_eq!(picks.len(), 2);
    assert_eq!((picks[0].1, picks[0].0.order.body.rate_pico), (100, 3_700_000_000));
    assert_eq!((picks[1].1, picks[1].0.order.body.rate_pico), (150, 3_750_000_000));
    // Best-execution blended average sits strictly between the two levels hit.
    let cost: u128 = picks.iter().map(|(e, take)| take * e.order.body.rate_pico).sum();
    let filled: u128 = picks.iter().map(|(_, take)| take).sum();
    assert_eq!(filled, 250);
    let avg = cost / filled;
    assert!(avg > 3_700_000_000 && avg < 3_750_000_000, "blended avg {avg} out of range");

    // --- MARKET beyond depth: partial fill = total available (600), rest unfilled. ---
    let picks = select_for_amount(&book, Side::SellXno, 1_000, &taker);
    let filled: u128 = picks.iter().map(|(_, take)| take).sum();
    assert_eq!(filled, 600, "market fills only the available depth");

    // --- MARKET on an empty book: zero fill, no phantom liquidity (audit #11). ---
    assert!(select_for_amount(&Book::default(), Side::SellXno, 100, &taker).is_empty());

    // --- Direction: the SellXmr book is best at the HIGHEST rate first. ---
    let mut xbook = Book::default();
    xbook.insert(sign_order(&m, body(&m, Side::SellXmr, 100, 3_600_000_000, 4)), 10, true);
    xbook.insert(sign_order(&m, body(&m, Side::SellXmr, 100, 3_900_000_000, 5)), 10, true);
    let picks = select_for_amount(&xbook, Side::SellXmr, 100, &taker);
    assert_eq!(picks[0].0.order.body.rate_pico, 3_900_000_000, "SellXmr best = highest rate");
}

/// E2E: a STOP-LIMIT trigger. A stop condition (VWAP crosses a stop level)
/// fires a LIMIT order at a distinct limit price; the wiring turns the fired
/// action into a concrete signed order that rests in the book at the limit
/// price — the exact chain the maker daemon runs locally (triggers are never
/// delegated to the relay).
#[test]
fn stop_limit_trigger_produces_a_signed_limit_order() {
    use dex_core::triggers::{order_for_fire, Action, Condition, Engine, OrderTemplate, Trigger};

    let m = maker();
    let mut e = Engine::default();
    let stop_level = 0.0034; // stop: fire when VWAP falls to/below this
    let limit_rate = 0.0032; // place the limit HERE (distinct from the stop)
    e.arm(Trigger::new(
        1,
        Condition::StopBelow { level: stop_level },
        Action::FireLimit { rate: limit_rate },
        10_000,
        None,
    ));
    let template = OrderTemplate {
        maker: m.pubkey,
        side: Side::SellXno,
        amount: 250,
        ttl: 3_600,
        pof_hash: [0xEE; 32],
    };

    // Above the stop: nothing fires.
    assert!(e.step(0.0036, 10).is_none());
    // VWAP crosses the stop → the limit action fires.
    let fired = e.step(0.0033, 11).expect("stop level crossed");
    assert_eq!(fired.action, Action::FireLimit { rate: limit_rate });

    // Wire the fired action into a concrete order and sign it.
    let body = order_for_fire(fired.action, &template, 0.0, 11, 42);
    assert_eq!(body.side, Side::SellXno);
    assert_eq!(body.amount, 250);
    assert_eq!(body.rate_pico, (limit_rate * 1e12) as u128, "uses the LIMIT price, not the stop");
    assert_eq!(body.expiry, 11 + 3_600);
    let order = sign_order(&m, body);
    assert!(order.verify(11), "stop-limit yields a valid, broadcastable signed limit order");

    // It rests in the book at its limit price and is matchable by a taker.
    let mut book = Book::default();
    assert!(book.insert(order, 11, true));
    let picks = select_for_amount(&book, Side::SellXno, 250, &[0x77; 32]);
    assert_eq!(picks.len(), 1);
    assert_eq!(picks[0].0.order.body.rate_pico, (limit_rate * 1e12) as u128);
}
