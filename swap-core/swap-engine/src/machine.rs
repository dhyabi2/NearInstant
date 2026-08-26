//! The deterministic swap state machine.
//!
//! Transport-agnostic: chain observations and counterparty messages come in
//! as [`Event`]s, the machine returns the [`Action`]s this party must perform
//! and rejects out-of-order events. One chunk is in flight at a time, so the
//! settled-value gap between the two legs never exceeds one chunk — the I1
//! loss bound — which the machine enforces as an internal invariant on every
//! transition.
//!
//! Per-chunk protocol (one-shot swap, Alice sells XNO, Bob sells XMR):
//! 1. Bob locks the XMR chunk to the joint XMR account (10-block maturity).
//! 2. Alice delivers the adaptor pre-signature on the XNO chunk claim, with
//!    the adaptor point committed to Bob's XMR key contribution.
//! 3. Bob broadcasts guard rung + completed claim — settling the XNO chunk
//!    and revealing the chunk secret on-chain.
//! 4. Alice extracts the secret and sweeps the XMR chunk.
//!
//! Aborts at any stage strand at most the in-flight chunk, and the stranded
//! side holds the I1 puzzle backstop for even that.

use crate::schedule::Schedule;

/// Monero's consensus output lock: an output cannot be spent until it is 10
/// blocks deep (~20 min). Alice must not reveal her adaptor pre-signature
/// (which lets Bob claim the XNO and expose the swap secret) against an XMR
/// lock shallower than this — a reorg could otherwise undo Bob's lock while he
/// keeps the XNO. This is the default maturity depth the machine gates on.
pub const MONERO_MATURITY_CONFIRMATIONS: u64 = 10;

/// Which side of the swap this machine instance runs for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Alice: pays XNO, receives XMR.
    XnoSeller,
    /// Bob: pays XMR, receives XNO.
    XmrSeller,
}

/// Stage within the current chunk (or of the session).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Waiting for both hostage bonds to confirm.
    AwaitBonds,
    /// Waiting for Bob's XMR chunk lock to confirm and mature.
    AwaitXmrLock,
    /// Waiting for Alice's adaptor pre-signature on the XNO claim.
    AwaitPresign,
    /// Guard rung broadcast; waiting for it to CONFIRM (cement) before the
    /// secret-revealing claim is completed. Splitting this out of the claim
    /// step (race finding 2) makes the I3 "confirm before reveal" gate a
    /// machine transition, not an executor convention.
    AwaitGuardConfirm,
    /// Waiting for Bob's completed claim to settle on Nano.
    AwaitXnoClaim,
    /// Waiting for Alice's XMR sweep to confirm.
    AwaitXmrSweep,
    /// All chunks settled; bonds returned cooperatively.
    Completed,
    /// Aborted; no further transitions.
    Aborted,
}

/// Inputs: chain observations and counterparty messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    BothBondsConfirmed,
    /// Bob's XMR chunk lock has been seen on-chain at `confirmations` depth.
    /// The machine only advances (and Alice only pre-signs) once `confirmations`
    /// reaches the maturity depth; a shallower observation keeps waiting.
    XmrLockObserved { chunk: usize, confirmations: u64 },
    PresignDelivered { chunk: usize },
    /// The guard rung is confirmed (cemented) — safe to complete and broadcast
    /// the secret-revealing claim (race finding 2).
    GuardConfirmed { chunk: usize },
    XnoClaimSettled { chunk: usize },
    XmrSweepConfirmed { chunk: usize },
    /// Bob's XMR lock, previously observed mature, has been dropped/shallowed by
    /// a chain reorg (race finding 1). In any pre-settlement stage this forces a
    /// fail-closed abort onto the recovery path, since a later observation of a
    /// regressed lock would otherwise be rejected as out-of-order and leave the
    /// machine stuck while the counterparty could still take the XNO leg.
    LockReorged { chunk: usize },
    /// The stage deadline passed, or the counterparty declared abort.
    Abort,
}

/// Outputs: what this party must do next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Lock the hostage bond (session start).
    LockBond,
    /// Bob: lock the XMR chunk to the joint account.
    LockXmrChunk { chunk: usize, amount: u128 },
    /// Alice: adaptor-pre-sign the XNO claim and deliver it.
    DeliverPresign { chunk: usize, amount: u128 },
    /// Bob: broadcast the guard rung (does NOT yet reveal the secret) and wait
    /// for it to confirm.
    BroadcastGuard { chunk: usize },
    /// Bob: the guard rung is cemented — complete the adaptor claim (revealing
    /// the secret) and broadcast it.
    CompleteAndBroadcastClaim { chunk: usize },
    /// Alice: extract the revealed secret and sweep the XMR chunk.
    SweepXmr { chunk: usize },
    /// Cooperatively return both bonds.
    ReturnBonds,
    /// Start the I1 puzzle backstop for the stranded in-flight chunk.
    TriggerRefundBackstop { chunk: usize },
}

#[derive(Debug, PartialEq, Eq)]
pub enum MachineError {
    /// Event arrived out of order for the current stage/chunk.
    UnexpectedEvent { stage: Stage, event: Event },
    /// The machine is terminal.
    Terminal,
    /// Internal invariant violated (a bug — never expected).
    InvariantViolated(&'static str),
}

/// The swap session state, tracking both legs' settled value.
#[derive(Clone, Debug)]
pub struct SwapMachine {
    role: Role,
    schedule: Schedule,
    stage: Stage,
    chunk: usize,
    /// Confirmation depth required on an XMR lock before Alice pre-signs.
    maturity_confirmations: u64,
    /// XNO value settled to Bob so far.
    xno_settled: u128,
    /// XMR value locked-and-swept to Alice so far.
    xmr_settled: u128,
    /// XMR value locked for the in-flight chunk but not yet swept.
    xmr_in_flight: u128,
}

impl SwapMachine {
    /// Construct with Monero's default 10-block maturity gate.
    pub fn new(role: Role, schedule: Schedule) -> Self {
        Self::with_maturity(role, schedule, MONERO_MATURITY_CONFIRMATIONS)
    }

    /// Construct with an explicit maturity depth (tests / non-default networks).
    pub fn with_maturity(role: Role, schedule: Schedule, maturity_confirmations: u64) -> Self {
        Self {
            role,
            schedule,
            stage: Stage::AwaitBonds,
            chunk: 0,
            maturity_confirmations,
            xno_settled: 0,
            xmr_settled: 0,
            xmr_in_flight: 0,
        }
    }

    pub fn stage(&self) -> Stage {
        self.stage
    }

    pub fn chunk(&self) -> usize {
        self.chunk
    }

    /// The I1 invariant, checked after every transition: the gap between what
    /// either side has irreversibly given and received never exceeds the
    /// largest chunk.
    fn check_invariant(&self) -> Result<(), MachineError> {
        let bound = self.schedule.max_at_risk();
        let gap = self.xno_settled.abs_diff(self.xmr_settled + self.xmr_in_flight);
        let flight_ok = self.xmr_in_flight <= bound;
        if gap <= bound && flight_ok {
            Ok(())
        } else {
            Err(MachineError::InvariantViolated(
                "settled-value gap exceeded one chunk",
            ))
        }
    }

    /// The maximum value this party could permanently lose if the
    /// counterparty vanished right now and every backstop failed. The I1
    /// design bounds this at one chunk at every reachable state.
    pub fn worst_case_loss(&self) -> u128 {
        match self.role {
            // Alice loses if XNO settled to Bob outruns XMR she has swept.
            Role::XnoSeller => self.xno_settled.saturating_sub(self.xmr_settled),
            // Bob loses if XMR locked+swept outruns XNO settled to him.
            Role::XmrSeller => {
                (self.xmr_settled + self.xmr_in_flight).saturating_sub(self.xno_settled)
            }
        }
    }

    fn actions_for(&self, all: Vec<(Option<Role>, Action)>) -> Vec<Action> {
        all.into_iter()
            .filter(|(who, _)| who.is_none() || *who == Some(self.role))
            .map(|(_, a)| a)
            .collect()
    }

    /// Feed one event; returns the actions for this party.
    pub fn handle(&mut self, event: Event) -> Result<Vec<Action>, MachineError> {
        if self.schedule.chunks.is_empty() {
            // A swap needs at least one chunk; an empty schedule (possible via
            // the public `Schedule` fields) would underflow the chunk index and
            // is rejected as an invariant violation rather than panicking.
            return Err(MachineError::InvariantViolated("empty chunk schedule"));
        }
        if matches!(self.stage, Stage::Completed | Stage::Aborted) {
            return Err(MachineError::Terminal);
        }
        if event == Event::Abort {
            let actions = self.abort_actions();
            self.stage = Stage::Aborted;
            self.check_invariant()?;
            return Ok(actions);
        }

        // Race finding 1: a reorg that drops/shallows the in-flight XMR lock at
        // any pre-settlement stage is a fail-closed abort onto the recovery
        // path — never a silently-rejected out-of-order event. Once the sweep
        // has confirmed the funds are already Alice's and a reorg is moot.
        if let Event::LockReorged { chunk } = event {
            if chunk == self.chunk
                && matches!(
                    self.stage,
                    Stage::AwaitPresign | Stage::AwaitGuardConfirm | Stage::AwaitXnoClaim
                )
            {
                let actions = self.abort_actions();
                self.stage = Stage::Aborted;
                self.check_invariant()?;
                return Ok(actions);
            }
            // Any other stage: a lock reorg is irrelevant (pre-lock) or too late
            // (post-sweep). Reject as unexpected so callers notice a bad feed.
            return Err(MachineError::UnexpectedEvent { stage: self.stage, event });
        }

        let amount = self.schedule.chunks[self.chunk.min(self.schedule.chunks.len() - 1)];
        let out = match (self.stage, event) {
            (Stage::AwaitBonds, Event::BothBondsConfirmed) => {
                self.stage = Stage::AwaitXmrLock;
                vec![(
                    Some(Role::XmrSeller),
                    Action::LockXmrChunk {
                        chunk: self.chunk,
                        amount,
                    },
                )]
            }
            (Stage::AwaitXmrLock, Event::XmrLockObserved { chunk, confirmations })
                if chunk == self.chunk =>
            {
                // Bob's XMR is committed the moment the lock is seen — his
                // funds are at risk from here, so it counts toward the loss
                // bound and (on abort) his refund backstop covers it.
                self.xmr_in_flight = amount;
                if confirmations >= self.maturity_confirmations {
                    // Matured: safe for Alice to reveal the adaptor pre-sig.
                    self.stage = Stage::AwaitPresign;
                    vec![(
                        Some(Role::XnoSeller),
                        Action::DeliverPresign {
                            chunk: self.chunk,
                            amount,
                        },
                    )]
                } else {
                    // Shallow lock: a reorg could still undo it. Hold in
                    // AwaitXmrLock and wait for a deeper observation — Alice
                    // does NOT pre-sign yet. No actions this step.
                    vec![]
                }
            }
            (Stage::AwaitPresign, Event::PresignDelivered { chunk }) if chunk == self.chunk => {
                // Broadcast the guard rung only — the secret is NOT revealed yet.
                self.stage = Stage::AwaitGuardConfirm;
                vec![(
                    Some(Role::XmrSeller),
                    Action::BroadcastGuard { chunk: self.chunk },
                )]
            }
            (Stage::AwaitGuardConfirm, Event::GuardConfirmed { chunk }) if chunk == self.chunk => {
                // Rung cemented → now safe to complete + broadcast the claim
                // (race finding 2: confirm-before-reveal is a real transition).
                self.stage = Stage::AwaitXnoClaim;
                vec![(
                    Some(Role::XmrSeller),
                    Action::CompleteAndBroadcastClaim { chunk: self.chunk },
                )]
            }
            (Stage::AwaitXnoClaim, Event::XnoClaimSettled { chunk }) if chunk == self.chunk => {
                self.xno_settled += amount;
                self.stage = Stage::AwaitXmrSweep;
                vec![(Some(Role::XnoSeller), Action::SweepXmr { chunk: self.chunk })]
            }
            (Stage::AwaitXmrSweep, Event::XmrSweepConfirmed { chunk }) if chunk == self.chunk => {
                self.xmr_settled += self.xmr_in_flight;
                self.xmr_in_flight = 0;
                self.chunk += 1;
                if self.chunk == self.schedule.chunks.len() {
                    self.stage = Stage::Completed;
                    vec![(None, Action::ReturnBonds)]
                } else {
                    self.stage = Stage::AwaitXmrLock;
                    let next = self.schedule.chunks[self.chunk];
                    vec![(
                        Some(Role::XmrSeller),
                        Action::LockXmrChunk {
                            chunk: self.chunk,
                            amount: next,
                        },
                    )]
                }
            }
            (stage, event) => return Err(MachineError::UnexpectedEvent { stage, event }),
        };
        // Audit #20: a tripped safety-net invariant must fail closed, not
        // leave the machine in a corrupt non-terminal state.
        if let Err(e) = self.check_invariant() {
            self.stage = Stage::Aborted;
            return Err(e);
        }
        Ok(self.actions_for(out))
    }

    fn abort_actions(&self) -> Vec<Action> {
        match (self.role, self.stage) {
            // Bob's XMR is locked but the chunk didn't finish: his backstop.
            // Covers every stage from lock-sight through the confirm-gate and
            // the claim wait — his funds are committed the moment the lock is
            // observed (even pre-maturity) and stay at risk until the sweep.
            (
                Role::XmrSeller,
                Stage::AwaitXmrLock
                | Stage::AwaitPresign
                | Stage::AwaitGuardConfirm
                | Stage::AwaitXnoClaim,
            ) if self.xmr_in_flight > 0 => {
                vec![Action::TriggerRefundBackstop { chunk: self.chunk }]
            }
            // Race finding 3: at AwaitXnoClaim Alice has already delivered her
            // pre-sig, so Bob can still complete the claim and take the XNO
            // leg. Aborting here is NOT a clean walk-away — Alice must keep the
            // sweep contingency (watch for the revealed secret, then sweep the
            // XMR she is owed) rather than abandon a recoverable chunk.
            (Role::XnoSeller, Stage::AwaitXnoClaim | Stage::AwaitXmrSweep) => {
                vec![Action::SweepXmr { chunk: self.chunk }]
            }
            _ => vec![],
        }
    }
}
