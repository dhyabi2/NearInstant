// swap_machine.js — the deterministic auto-responder "brain", ported 1:1 from
// swap-core/swap-engine (schedule.rs + machine.rs). PURE logic: chain/counterparty
// observations go in as Events, the Actions this party must perform come out. No
// crypto and no I/O live here — an event source (chain watchers) drives it and an
// executor performs the returned actions. Loss is bounded to one chunk at every
// reachable state (I1); the guard-confirm gate (confirm-before-reveal) and the
// reorg→fail-closed-abort path are machine transitions, not conventions.
//
// Verified against the Rust reference (`cargo test -p swap-engine`) and by the
// companion node test (schedule vectors + happy path + abort + out-of-order +
// reorg). Value fields use BigInt (u128 semantics); counts/indices are Numbers.
(function (root) {
  "use strict";

  const Role = { XnoSeller: "XnoSeller", XmrSeller: "XmrSeller" };
  const Stage = {
    AwaitBonds: "AwaitBonds", AwaitXmrLock: "AwaitXmrLock", AwaitPresign: "AwaitPresign",
    AwaitGuardConfirm: "AwaitGuardConfirm", AwaitXnoClaim: "AwaitXnoClaim",
    AwaitXmrSweep: "AwaitXmrSweep", Completed: "Completed", Aborted: "Aborted",
  };
  const MONERO_MATURITY_CONFIRMATIONS = 10;

  class MachineError extends Error {
    constructor(kind, detail) { super(kind + (detail ? ": " + detail : "")); this.kind = kind; this.detail = detail || null; }
  }
  const bmax = (a, b) => (a > b ? a : b);
  const absDiff = (a, b) => (a > b ? a - b : b - a);
  const satSub = (a, b) => (a > b ? a - b : 0n);

  // ---- Schedule (I1 chunking: an abort strands at most one chunk) ----
  const ScheduleError = { ZeroTotal: "ZeroTotal", BadBounds: "BadBounds", TooManyChunks: "TooManyChunks" };
  function buildSchedule(total, minChunk, maxChunk, maxChunks) {
    total = BigInt(total); minChunk = BigInt(minChunk); maxChunk = BigInt(maxChunk);
    if (total === 0n) throw new MachineError(ScheduleError.ZeroTotal);
    if (maxChunk === 0n || minChunk > maxChunk) throw new MachineError(ScheduleError.BadBounds);
    const chunks = [];
    let remaining = total;
    while (remaining > 0n) {
      if (chunks.length >= maxChunks) throw new MachineError(ScheduleError.TooManyChunks);
      if (remaining <= maxChunk) { chunks.push(remaining); remaining = 0n; }
      else if (remaining - maxChunk < minChunk) {
        // Tail below min_chunk but folding would exceed max_chunk: split into two
        // balanced chunks, each ≤ max_chunk. This branch pushes TWO chunks.
        if (chunks.length + 2 > maxChunks) throw new MachineError(ScheduleError.TooManyChunks);
        const half = remaining / 2n;
        chunks.push(half); chunks.push(remaining - half); remaining = 0n;
      } else { chunks.push(maxChunk); remaining -= maxChunk; }
    }
    return { chunks };
  }
  const scheduleTotal = (s) => s.chunks.reduce((a, c) => a + c, 0n);
  const maxAtRisk = (s) => s.chunks.reduce((m, c) => (c > m ? c : m), 0n);

  // ---- SwapMachine ----
  class SwapMachine {
    constructor(role, schedule, maturityConfirmations) {
      this.role = role;
      this.schedule = schedule;
      this.stage = Stage.AwaitBonds;
      this.chunk = 0;
      this.maturity = maturityConfirmations == null ? MONERO_MATURITY_CONFIRMATIONS : maturityConfirmations;
      this.xnoSettled = 0n;
      this.xmrSettled = 0n;
      this.xmrInFlight = 0n;
    }

    checkInvariant() {
      const bound = maxAtRisk(this.schedule);
      const gap = absDiff(this.xnoSettled, this.xmrSettled + this.xmrInFlight);
      const flightOk = this.xmrInFlight <= bound;
      if (!(gap <= bound && flightOk)) throw new MachineError("InvariantViolated", "settled-value gap exceeded one chunk");
    }

    worstCaseLoss() {
      return this.role === Role.XnoSeller
        ? satSub(this.xnoSettled, this.xmrSettled)
        : satSub(this.xmrSettled + this.xmrInFlight, this.xnoSettled);
    }

    actionsFor(all) {
      return all.filter(([who]) => who === null || who === this.role).map(([, a]) => a);
    }

    abortActions() {
      const bobStrand = this.role === Role.XmrSeller &&
        [Stage.AwaitXmrLock, Stage.AwaitPresign, Stage.AwaitGuardConfirm, Stage.AwaitXnoClaim].includes(this.stage) &&
        this.xmrInFlight > 0n;
      if (bobStrand) return [{ type: "TriggerRefundBackstop", chunk: this.chunk }];
      // Alice at/after claim: keep the sweep contingency (not a clean walk-away).
      if (this.role === Role.XnoSeller && [Stage.AwaitXnoClaim, Stage.AwaitXmrSweep].includes(this.stage))
        return [{ type: "SweepXmr", chunk: this.chunk }];
      return [];
    }

    // Feed one event; returns the actions for THIS party (throws MachineError).
    handle(event) {
      if (this.schedule.chunks.length === 0) throw new MachineError("InvariantViolated", "empty chunk schedule");
      if (this.stage === Stage.Completed || this.stage === Stage.Aborted) throw new MachineError("Terminal");

      if (event.type === "Abort") {
        const actions = this.abortActions(); this.stage = Stage.Aborted; this.checkInvariant(); return actions;
      }
      if (event.type === "LockReorged") {
        if (event.chunk === this.chunk &&
            [Stage.AwaitPresign, Stage.AwaitGuardConfirm, Stage.AwaitXnoClaim].includes(this.stage)) {
          const actions = this.abortActions(); this.stage = Stage.Aborted; this.checkInvariant(); return actions;
        }
        throw new MachineError("UnexpectedEvent", this.stage + "/LockReorged");
      }

      const amount = this.schedule.chunks[Math.min(this.chunk, this.schedule.chunks.length - 1)];
      let out;
      const s = this.stage, t = event.type;
      if (s === Stage.AwaitBonds && t === "BothBondsConfirmed") {
        this.stage = Stage.AwaitXmrLock;
        out = [[Role.XmrSeller, { type: "LockXmrChunk", chunk: this.chunk, amount }]];
      } else if (s === Stage.AwaitXmrLock && t === "XmrLockObserved" && event.chunk === this.chunk) {
        this.xmrInFlight = amount;
        if (event.confirmations >= this.maturity) {
          this.stage = Stage.AwaitPresign;
          out = [[Role.XnoSeller, { type: "DeliverPresign", chunk: this.chunk, amount }]];
        } else { out = []; } // shallow lock: hold, no pre-sign yet
      } else if (s === Stage.AwaitPresign && t === "PresignDelivered" && event.chunk === this.chunk) {
        this.stage = Stage.AwaitGuardConfirm;
        out = [[Role.XmrSeller, { type: "BroadcastGuard", chunk: this.chunk }]];
      } else if (s === Stage.AwaitGuardConfirm && t === "GuardConfirmed" && event.chunk === this.chunk) {
        this.stage = Stage.AwaitXnoClaim;
        out = [[Role.XmrSeller, { type: "CompleteAndBroadcastClaim", chunk: this.chunk }]];
      } else if (s === Stage.AwaitXnoClaim && t === "XnoClaimSettled" && event.chunk === this.chunk) {
        this.xnoSettled += amount; this.stage = Stage.AwaitXmrSweep;
        out = [[Role.XnoSeller, { type: "SweepXmr", chunk: this.chunk }]];
      } else if (s === Stage.AwaitXmrSweep && t === "XmrSweepConfirmed" && event.chunk === this.chunk) {
        this.xmrSettled += this.xmrInFlight; this.xmrInFlight = 0n; this.chunk += 1;
        if (this.chunk === this.schedule.chunks.length) {
          this.stage = Stage.Completed; out = [[null, { type: "ReturnBonds" }]];
        } else {
          this.stage = Stage.AwaitXmrLock;
          const next = this.schedule.chunks[this.chunk];
          out = [[Role.XmrSeller, { type: "LockXmrChunk", chunk: this.chunk, amount: next }]];
        }
      } else {
        throw new MachineError("UnexpectedEvent", s + "/" + t);
      }
      try { this.checkInvariant(); } catch (e) { this.stage = Stage.Aborted; throw e; }
      return this.actionsFor(out);
    }
  }

  const api = { Role, Stage, MachineError, ScheduleError, MONERO_MATURITY_CONFIRMATIONS,
    buildSchedule, scheduleTotal, maxAtRisk, SwapMachine };
  root.XnoxmrSwapMachine = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
