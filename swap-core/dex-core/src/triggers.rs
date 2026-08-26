//! B3: advanced orders without a trigger engine.
//!
//! Stops, stop-limits, OCO pairs, and trailing stops are signed intents held
//! and evaluated **locally** against the settled-trade VWAP. Nothing is
//! delegated; triggers fire only while the user's own device (or their I6
//! device quorum) is up — stated plainly, never simulated.

use crate::order::{Bytes32, OrderBody, Side};

/// What to do when a trigger condition is met.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Action {
    /// Broadcast the pre-authorized market intent.
    FireMarket,
    /// Place the pre-signed limit at `rate`.
    FireLimit { rate: f64 },
}

/// The wiring from the local trigger engine to the signed-order layer: the
/// order a stop / stop-limit should place when it fires. A stop-limit is a
/// `Condition::Stop{Above,Below}` paired with `Action::FireLimit { rate }` and
/// this template — when the condition crosses, [`order_for_fire`] turns the
/// fired action into a concrete [`OrderBody`] the caller signs and gossips.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OrderTemplate {
    pub maker: Bytes32,
    pub side: Side,
    /// Order size (XNO milli-units, same units the book/relay use).
    pub amount: u128,
    /// Order lifetime after firing (seconds), stamped as `now + ttl`.
    pub ttl: u64,
    pub pof_hash: Bytes32,
}

/// Build the concrete unsigned order a fired trigger should place. A stop-limit
/// (`FireLimit { rate }`) uses the trigger's own limit price; a plain stop
/// (`FireMarket`) uses `marketable_rate` — the caller's current cross-the-spread
/// price. The result is ready to sign (ed25519-blake2b) and gossip to the relay.
/// Rates are XMR-per-XNO scaled to pico (×1e12), matching the wire format.
pub fn order_for_fire(
    action: Action,
    template: &OrderTemplate,
    marketable_rate: f64,
    now: u64,
    nonce: u64,
) -> OrderBody {
    let rate = match action {
        Action::FireLimit { rate } => rate,
        Action::FireMarket => marketable_rate,
    };
    OrderBody {
        maker: template.maker,
        side: template.side,
        amount: template.amount,
        rate_pico: (rate.max(0.0) * 1e12) as u128,
        expiry: now.saturating_add(template.ttl),
        nonce,
        pof_hash: template.pof_hash,
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Condition {
    /// Fire when VWAP falls to or below `level` (stop-loss).
    StopBelow { level: f64 },
    /// Fire when VWAP rises to or above `level` (take-profit / breakout).
    StopAbove { level: f64 },
    /// Trailing stop: fire when VWAP drops `distance` below the highest
    /// VWAP seen since arming.
    Trailing { distance: f64 },
}

/// One armed trigger.
#[derive(Clone, Debug)]
pub struct Trigger {
    pub id: u64,
    pub condition: Condition,
    pub action: Action,
    /// Dead after this time (checked against block-derived time).
    pub expiry: u64,
    /// OCO group: when one member fires, the rest are cancelled atomically.
    pub oco_group: Option<u64>,
    /// Internal high-water mark for trailing stops.
    watermark: f64,
}

impl Trigger {
    pub fn new(
        id: u64,
        condition: Condition,
        action: Action,
        expiry: u64,
        oco_group: Option<u64>,
    ) -> Self {
        Self {
            id,
            condition,
            action,
            expiry,
            oco_group,
            watermark: f64::NEG_INFINITY,
        }
    }
}

/// The local trigger engine.
#[derive(Default)]
pub struct Engine {
    triggers: Vec<Trigger>,
}

/// The outcome of one evaluation step.
#[derive(Debug, PartialEq)]
pub struct Fired {
    pub id: u64,
    pub action: Action,
    /// Ids cancelled because they shared the firing trigger's OCO group.
    pub cancelled: Vec<u64>,
}

impl Engine {
    pub fn arm(&mut self, t: Trigger) {
        self.triggers.push(t);
    }

    pub fn cancel(&mut self, id: u64) {
        self.triggers.retain(|t| t.id != id);
    }

    pub fn armed(&self) -> usize {
        self.triggers.len()
    }

    /// Evaluate against the latest settled-trade VWAP. At most one trigger
    /// fires per step (deterministic: lowest id first), and its OCO group is
    /// cancelled atomically before anything else can fire (B3: exclusivity
    /// is client-enforced).
    pub fn step(&mut self, vwap: f64, now: u64) -> Option<Fired> {
        self.triggers.retain(|t| t.expiry > now);
        self.triggers.sort_by_key(|t| t.id);
        // Update trailing watermarks first.
        for t in &mut self.triggers {
            if matches!(t.condition, Condition::Trailing { .. }) {
                t.watermark = t.watermark.max(vwap);
            }
        }
        let fired_idx = self.triggers.iter().position(|t| match t.condition {
            Condition::StopBelow { level } => vwap <= level,
            Condition::StopAbove { level } => vwap >= level,
            Condition::Trailing { distance } => {
                t.watermark.is_finite() && vwap <= t.watermark - distance
            }
        })?;
        let fired = self.triggers.remove(fired_idx);
        let mut cancelled = Vec::new();
        if let Some(g) = fired.oco_group {
            self.triggers.retain(|t| {
                if t.oco_group == Some(g) {
                    cancelled.push(t.id);
                    false
                } else {
                    true
                }
            });
        }
        Some(Fired {
            id: fired.id,
            action: fired.action,
            cancelled,
        })
    }
}
