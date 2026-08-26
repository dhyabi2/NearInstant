// swap_responder.js — the driver that turns the deterministic brain
// (swap_machine.js) into an unattended settlement responder. It owns a
// SwapMachine, feeds it chain/peer Events, and dispatches each returned Action
// to an EXECUTOR (the map Action -> real settlement primitive). This is the
// assembly layer: the event source (chain watchers) calls feed(event); the
// executor performs LockXmrChunk / DeliverPresign / BroadcastGuard /
// CompleteAndBroadcastClaim / SweepXmr / ReturnBonds / TriggerRefundBackstop /
// LockBond via the existing wasm + wallet calls.
//
// PURE wiring — no crypto, no broadcast here. In tests the executor is mocked to
// record calls; in production it is the real settlement (which needs on-chain).
// Verified offline: the full happy path and the abort/refund path dispatch the
// correct settlement calls, in order, for each role.
(function (root) {
  "use strict";
  const SM = root.XnoxmrSwapMachine || (typeof require !== "undefined" ? require("./swap_machine.js") : null);
  if (!SM) throw new Error("swap_machine.js must load before swap_responder.js");

  const ACTION_TYPES = [
    "LockBond", "LockXmrChunk", "DeliverPresign", "BroadcastGuard",
    "CompleteAndBroadcastClaim", "SweepXmr", "ReturnBonds", "TriggerRefundBackstop",
  ];

  // executor: { <ActionType>: async (action, ctx) => {...} }. ctx = {role, stage,
  // machine}. Any action type the machine can emit must have an executor entry
  // (validated up front so a missing wire fails fast, not mid-swap).
  function makeResponder(role, schedule, executor, opts) {
    opts = opts || {};
    for (const t of ACTION_TYPES) {
      if (typeof executor[t] !== "function") throw new Error("executor missing action: " + t);
    }
    const machine = new SM.SwapMachine(role, schedule, opts.maturity);
    const log = [];               // ordered trace of dispatched actions (for tests/observability)
    let aborted = false;

    // Feed one Event; run the machine; dispatch its Actions to the executor in
    // order. On a machine error (out-of-order / invariant), record and rethrow —
    // the caller (event source) decides whether to Abort.
    async function feed(event) {
      let actions;
      try {
        actions = machine.handle(event);
      } catch (e) {
        log.push({ event: event.type, error: e.kind || e.message });
        throw e;
      }
      if (machine.stage === SM.Stage.Aborted) aborted = true;
      for (const a of actions) {
        log.push({ action: a.type, chunk: a.chunk });
        await executor[a.type](a, { role, stage: machine.stage, machine });
      }
      return actions;
    }

    // Convenience: drive an ordered list of events (used by tests and by a
    // deterministic replay on resume).
    async function drive(events) {
      const done = [];
      for (const ev of events) done.push(await feed(ev));
      return done;
    }

    return {
      feed, drive, log,
      role,
      stage: () => machine.stage,
      chunk: () => machine.chunk,
      worstCaseLoss: () => machine.worstCaseLoss(),
      aborted: () => aborted,
      _machine: machine,
    };
  }

  const api = { makeResponder, ACTION_TYPES };
  root.XnoxmrSwapResponder = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
