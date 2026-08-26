//! Block 4 unit battery: schedules (loss bound by construction), pricing
//! (decay behavior), and the state machine walked through the happy path,
//! every abort point (the S06 re-run), and out-of-order event rejection.

use swap_engine::machine::{Action, Event, MachineError, Role, Stage, SwapMachine};
use swap_engine::premium::{premium, volatility, vwap, PremiumParams, SettledTrade};
use swap_engine::schedule::{Schedule, ScheduleError};

#[test]
fn schedule_sums_bounds_and_folds_dust() {
    let s = Schedule::build(1_000, 50, 300, 100).unwrap();
    assert_eq!(s.total(), 1_000);
    // Audit #14: no chunk exceeds the max_chunk cap (dust tail is split, not folded).
    assert!(s.chunks.iter().all(|&c| c <= 300));
    assert!(s.max_at_risk() <= 300);

    // Audit #14: a sub-min dust tail is split into two balanced chunks, each
    // at or below max_chunk — never one over-cap chunk.
    let s = Schedule::build(301, 50, 300, 100).unwrap();
    assert_eq!(s.chunks, vec![150, 151]);
    assert!(s.chunks.iter().all(|&c| c <= 300));
    assert_eq!(s.total(), 301);

    // Exact multiples split cleanly.
    let s = Schedule::build(900, 50, 300, 100).unwrap();
    assert_eq!(s.chunks, vec![300, 300, 300]);

    assert_eq!(Schedule::build(0, 1, 10, 5), Err(ScheduleError::ZeroTotal));
    assert_eq!(Schedule::build(10, 5, 4, 5), Err(ScheduleError::BadBounds));
    assert_eq!(
        Schedule::build(1_000, 1, 10, 5),
        Err(ScheduleError::TooManyChunks)
    );
}

#[test]
fn empty_schedule_is_rejected_not_panicked() {
    // An empty schedule (constructible via the public field) must be refused as
    // an invariant violation rather than underflowing the chunk index.
    let mut m = SwapMachine::new(Role::XnoSeller, Schedule { chunks: vec![] });
    assert_eq!(
        m.handle(Event::BothBondsConfirmed),
        Err(MachineError::InvariantViolated("empty chunk schedule"))
    );
}

#[test]
fn vwap_and_volatility_decay_and_premium_shrinks() {
    let trades = vec![
        SettledTrade { price: 100.0, size: 1.0, timestamp: 0 },
        SettledTrade { price: 110.0, size: 1.0, timestamp: 500 },
        SettledTrade { price: 130.0, size: 1.0, timestamp: 1_000 },
    ];
    // Recent trades dominate: VWAP sits nearer the latest price.
    let v = vwap(&trades, 1_000, 300.0).unwrap();
    assert!(v > 115.0 && v < 130.0, "decayed vwap {v}");
    // No trades → no number (empty market shown empty).
    assert!(vwap(&[], 0, 300.0).is_none());

    let vol = volatility(&trades, 1_000, 600.0).unwrap();
    assert!(vol > 0.0);

    // Premium decays toward the floor as the swap progresses, and a calmer
    // market prices a smaller option.
    let p = PremiumParams { base: 0.001, k: 1.0, expected_duration: 600.0, duration_unit: 600.0 };
    let start = premium(&p, vol, 0.0);
    let mid = premium(&p, vol, 300.0);
    let done = premium(&p, vol, 600.0);
    assert!(start > mid && mid > done);
    assert!((done - 0.001).abs() < 1e-12);
    assert!(premium(&p, vol / 2.0, 0.0) < start);
}

fn drive_happy_path(role: Role, chunks: usize) -> SwapMachine {
    let schedule = Schedule::build(100 * chunks as u128, 1, 100, chunks).unwrap();
    let mut m = SwapMachine::new(role, schedule);
    m.handle(Event::BothBondsConfirmed).unwrap();
    for i in 0..chunks {
        m.handle(Event::XmrLockObserved { chunk: i, confirmations: 10 }).unwrap();
        m.handle(Event::PresignDelivered { chunk: i }).unwrap();
        m.handle(Event::GuardConfirmed { chunk: i }).unwrap();
        m.handle(Event::XnoClaimSettled { chunk: i }).unwrap();
        m.handle(Event::XmrSweepConfirmed { chunk: i }).unwrap();
        // The loss bound holds at every settled boundary.
        assert!(m.worst_case_loss() <= 100);
    }
    m
}

#[test]
fn happy_path_completes_and_returns_bonds() {
    let schedule = Schedule::build(300, 1, 100, 10).unwrap();
    let mut alice = SwapMachine::new(Role::XnoSeller, schedule.clone());
    let mut bob = SwapMachine::new(Role::XmrSeller, schedule);

    // Bond confirmation instructs Bob (and only Bob) to lock the first chunk.
    assert_eq!(alice.handle(Event::BothBondsConfirmed).unwrap(), vec![]);
    assert_eq!(
        bob.handle(Event::BothBondsConfirmed).unwrap(),
        vec![Action::LockXmrChunk { chunk: 0, amount: 100 }]
    );

    for i in 0..3 {
        assert_eq!(
            alice.handle(Event::XmrLockObserved { chunk: i, confirmations: 10 }).unwrap(),
            vec![Action::DeliverPresign { chunk: i, amount: 100 }]
        );
        bob.handle(Event::XmrLockObserved { chunk: i, confirmations: 10 }).unwrap();
        // Presign delivered → Bob broadcasts the guard rung only (no secret yet).
        assert_eq!(
            bob.handle(Event::PresignDelivered { chunk: i }).unwrap(),
            vec![Action::BroadcastGuard { chunk: i }]
        );
        alice.handle(Event::PresignDelivered { chunk: i }).unwrap();
        // Rung cemented → only now does Bob complete + broadcast the claim.
        assert_eq!(
            bob.handle(Event::GuardConfirmed { chunk: i }).unwrap(),
            vec![Action::CompleteAndBroadcastClaim { chunk: i }]
        );
        alice.handle(Event::GuardConfirmed { chunk: i }).unwrap();
        assert_eq!(
            alice.handle(Event::XnoClaimSettled { chunk: i }).unwrap(),
            vec![Action::SweepXmr { chunk: i }]
        );
        bob.handle(Event::XnoClaimSettled { chunk: i }).unwrap();
        let a = alice.handle(Event::XmrSweepConfirmed { chunk: i }).unwrap();
        let b = bob.handle(Event::XmrSweepConfirmed { chunk: i }).unwrap();
        if i == 2 {
            assert_eq!(a, vec![Action::ReturnBonds]);
            assert_eq!(b, vec![Action::ReturnBonds]);
        }
    }
    assert_eq!(alice.stage(), Stage::Completed);
    assert_eq!(bob.stage(), Stage::Completed);
    assert_eq!(alice.worst_case_loss(), 0);
    assert_eq!(bob.worst_case_loss(), 0);
}

/// S06 re-run: abort at EVERY event boundary of a 3-chunk swap; each party's
/// worst-case loss never exceeds one chunk, and the stranded side is told to
/// trigger its backstop (Bob) or finish its unilateral sweep (Alice).
#[test]
fn abort_at_every_point_bounds_loss_to_one_chunk() {
    let chunk_val = 100u128;
    let events: Vec<Vec<Event>> = (0..3)
        .map(|i| {
            vec![
                Event::XmrLockObserved { chunk: i, confirmations: 10 },
                Event::PresignDelivered { chunk: i },
                Event::GuardConfirmed { chunk: i },
                Event::XnoClaimSettled { chunk: i },
                Event::XmrSweepConfirmed { chunk: i },
            ]
        })
        .collect();
    let flat: Vec<Event> = events.into_iter().flatten().collect();

    for abort_after in 0..=flat.len() {
        for role in [Role::XnoSeller, Role::XmrSeller] {
            let schedule = Schedule::build(300, 1, 100, 10).unwrap();
            let mut m = SwapMachine::new(role, schedule);
            m.handle(Event::BothBondsConfirmed).unwrap();
            for e in &flat[..abort_after] {
                m.handle(*e).unwrap();
            }
            let stage = m.stage();
            let actions = if stage != Stage::Completed {
                m.handle(Event::Abort).unwrap()
            } else {
                vec![]
            };
            assert!(
                m.worst_case_loss() <= chunk_val,
                "loss {} > chunk at abort point {abort_after} for {role:?}",
                m.worst_case_loss()
            );
            // The stranded party is routed to its recovery path.
            match (role, stage) {
                (
                    Role::XmrSeller,
                    Stage::AwaitPresign | Stage::AwaitGuardConfirm | Stage::AwaitXnoClaim,
                ) => {
                    assert!(actions
                        .iter()
                        .any(|a| matches!(a, Action::TriggerRefundBackstop { .. })));
                }
                // Race finding 3: Alice keeps the sweep contingency from the
                // moment her pre-sig is out (AwaitXnoClaim), not just after the
                // claim settles (AwaitXmrSweep).
                (Role::XnoSeller, Stage::AwaitXnoClaim | Stage::AwaitXmrSweep) => {
                    assert!(actions.iter().any(|a| matches!(a, Action::SweepXmr { .. })));
                }
                _ => {}
            }
        }
    }
}

#[test]
fn out_of_order_events_are_rejected_and_terminal_is_final() {
    let schedule = Schedule::build(200, 1, 100, 10).unwrap();
    let mut m = SwapMachine::new(Role::XnoSeller, schedule);

    // Claim before bonds: rejected.
    assert!(matches!(
        m.handle(Event::XnoClaimSettled { chunk: 0 }),
        Err(MachineError::UnexpectedEvent { .. })
    ));
    m.handle(Event::BothBondsConfirmed).unwrap();
    // Wrong chunk index: rejected.
    assert!(matches!(
        m.handle(Event::XmrLockObserved { chunk: 1, confirmations: 10 }),
        Err(MachineError::UnexpectedEvent { .. })
    ));
    // Skipping the presign stage: rejected.
    m.handle(Event::XmrLockObserved { chunk: 0, confirmations: 10 }).unwrap();
    assert!(matches!(
        m.handle(Event::XnoClaimSettled { chunk: 0 }),
        Err(MachineError::UnexpectedEvent { .. })
    ));

    // After abort, everything is rejected.
    m.handle(Event::Abort).unwrap();
    assert_eq!(m.stage(), Stage::Aborted);
    assert!(matches!(
        m.handle(Event::PresignDelivered { chunk: 0 }),
        Err(MachineError::Terminal)
    ));

    // A completed machine is terminal too.
    let mut done = drive_happy_path(Role::XmrSeller, 2);
    assert!(matches!(done.handle(Event::Abort), Err(MachineError::Terminal)));
}

/// Audit (schedule off-by-one): the two-chunk dust split must not push the
/// count past max_chunks. Previously build(23,5,10,2) yielded 3 chunks.
#[test]
fn dust_split_respects_max_chunks() {
    // 23 with max_chunk 10 → [10, then split 13→(6,7)] = 3 chunks, but cap is 2.
    assert_eq!(Schedule::build(23, 5, 10, 2), Err(ScheduleError::TooManyChunks));
    // With room for the split, it succeeds and stays within the cap.
    let s = Schedule::build(23, 5, 10, 3).unwrap();
    assert_eq!(s.total(), 23);
    assert!(s.chunks.len() <= 3);
    assert!(s.chunks.iter().all(|&c| c <= 10));
}

/// Monero 10-block maturity gate: Alice must NOT deliver her adaptor
/// pre-signature until Bob's XMR lock is mature. A shallow observation keeps
/// the machine in AwaitXmrLock with no action; a mature one advances.
#[test]
fn alice_holds_presign_until_xmr_lock_matures() {
    let schedule = Schedule::build(100, 1, 100, 1).unwrap();
    let mut alice = SwapMachine::new(Role::XnoSeller, schedule);
    alice.handle(Event::BothBondsConfirmed).unwrap();

    // Shallow lock (1 of 10 confirmations): no presign, still awaiting the lock.
    let acts = alice.handle(Event::XmrLockObserved { chunk: 0, confirmations: 1 }).unwrap();
    assert!(acts.is_empty(), "must not pre-sign against a shallow lock");
    assert_eq!(alice.stage(), Stage::AwaitXmrLock);
    // Bob's funds already count toward the bound (his risk starts at lock sight).
    assert!(alice.worst_case_loss() <= 100);

    // Still shallow at 9: still holding.
    let acts = alice.handle(Event::XmrLockObserved { chunk: 0, confirmations: 9 }).unwrap();
    assert!(acts.is_empty());
    assert_eq!(alice.stage(), Stage::AwaitXmrLock);

    // Matured at 10: now Alice delivers the pre-signature.
    let acts = alice.handle(Event::XmrLockObserved { chunk: 0, confirmations: 10 }).unwrap();
    assert_eq!(acts, vec![Action::DeliverPresign { chunk: 0, amount: 100 }]);
    assert_eq!(alice.stage(), Stage::AwaitPresign);
}

/// Bob aborting while his lock is still maturing must trigger his refund
/// backstop (his XMR is already committed on-chain).
#[test]
fn bob_abort_during_immature_lock_triggers_backstop() {
    let schedule = Schedule::build(100, 1, 100, 1).unwrap();
    let mut bob = SwapMachine::new(Role::XmrSeller, schedule);
    bob.handle(Event::BothBondsConfirmed).unwrap();
    bob.handle(Event::XmrLockObserved { chunk: 0, confirmations: 2 }).unwrap();
    assert_eq!(bob.stage(), Stage::AwaitXmrLock);
    let acts = bob.handle(Event::Abort).unwrap();
    assert!(acts.iter().any(|a| matches!(a, Action::TriggerRefundBackstop { chunk: 0 })));
    assert!(bob.worst_case_loss() <= 100);
}

/// Race finding 1: a Monero reorg that drops the in-flight lock AFTER the
/// maturity gate must force a fail-closed abort onto the recovery path, not be
/// rejected as an out-of-order event that leaves the machine stuck.
#[test]
fn lock_reorg_after_maturity_gate_forces_recovery() {
    let schedule = Schedule::build(100, 1, 100, 1).unwrap();

    // Bob at the guard-confirm wait: LockReorged → abort + refund backstop.
    let mut bob = SwapMachine::new(Role::XmrSeller, schedule.clone());
    bob.handle(Event::BothBondsConfirmed).unwrap();
    bob.handle(Event::XmrLockObserved { chunk: 0, confirmations: 10 }).unwrap();
    bob.handle(Event::PresignDelivered { chunk: 0 }).unwrap(); // AwaitGuardConfirm
    let acts = bob.handle(Event::LockReorged { chunk: 0 }).unwrap();
    assert_eq!(bob.stage(), Stage::Aborted);
    assert!(acts.iter().any(|a| matches!(a, Action::TriggerRefundBackstop { chunk: 0 })));
    assert!(bob.worst_case_loss() <= 100);

    // Alice at AwaitXnoClaim: LockReorged → abort but KEEP the sweep contingency.
    let mut alice = SwapMachine::new(Role::XnoSeller, schedule.clone());
    alice.handle(Event::BothBondsConfirmed).unwrap();
    alice.handle(Event::XmrLockObserved { chunk: 0, confirmations: 10 }).unwrap();
    alice.handle(Event::PresignDelivered { chunk: 0 }).unwrap();
    alice.handle(Event::GuardConfirmed { chunk: 0 }).unwrap(); // AwaitXnoClaim
    let acts = alice.handle(Event::LockReorged { chunk: 0 }).unwrap();
    assert_eq!(alice.stage(), Stage::Aborted);
    assert!(acts.iter().any(|a| matches!(a, Action::SweepXmr { chunk: 0 })));

    // A reorg reported once the swap is complete is moot → terminal.
    let mut done = SwapMachine::new(Role::XmrSeller, schedule);
    done.handle(Event::BothBondsConfirmed).unwrap();
    done.handle(Event::XmrLockObserved { chunk: 0, confirmations: 10 }).unwrap();
    done.handle(Event::PresignDelivered { chunk: 0 }).unwrap();
    done.handle(Event::GuardConfirmed { chunk: 0 }).unwrap();
    done.handle(Event::XnoClaimSettled { chunk: 0 }).unwrap();
    done.handle(Event::XmrSweepConfirmed { chunk: 0 }).unwrap();
    assert!(matches!(done.handle(Event::LockReorged { chunk: 0 }), Err(MachineError::Terminal)));
}
