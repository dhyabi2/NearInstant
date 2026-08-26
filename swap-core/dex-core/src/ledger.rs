//! G2: the deterministic earnings ledger.
//!
//! A pure function from the signed event log to an income statement:
//! identical output on every client, cross-checkable against on-chain
//! anchors. Costs (PoW, relay tips, bond opportunity cost) are netted
//! honestly; premium income accrues along its decay; inventory marks to the
//! settled-trade VWAP.

/// One event in the append-only signed log (signature verification happens
/// at ingestion; the ledger consumes verified events).
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// A fill: spread income captured, tagged by strategy.
    Fill { t: u64, strategy: u32, spread_xmr: f64 },
    /// Premium collected at match time, accruing linearly over `duration`.
    Premium { t: u64, strategy: u32, amount_xmr: f64, duration: u64 },
    /// Service income (relay/delegate/PoW receipts), by service tag.
    Service { t: u64, service: u32, amount_xmr: f64 },
    /// A cost paid (PoW purchased, relay tip, fee).
    Cost { t: u64, amount_xmr: f64 },
    /// Bond locked (opportunity cost accrues) / released.
    BondLock { t: u64, amount_xmr: f64 },
    BondRelease { t: u64, amount_xmr: f64 },
    /// Inventory delta in base units (for mark-to-VWAP unrealized P&L).
    InventoryDelta { t: u64, xno: f64, xmr: f64 },
}

/// The income statement at `now`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Statement {
    pub spread_income: f64,
    /// Premium recognized so far (decay-accrued, G2: no premature revenue).
    pub premium_recognized: f64,
    /// Premium collected but not yet recognized.
    pub premium_deferred: f64,
    pub service_income: f64,
    pub costs: f64,
    /// Imputed opportunity cost of bonded capital.
    pub bond_opportunity_cost: f64,
    /// Inventory position (base units).
    pub inventory_xno: f64,
    pub inventory_xmr: f64,
    /// Mark-to-VWAP unrealized value of the XNO leg (XMR-eq).
    pub unrealized_xmr_eq: f64,
    /// Per-strategy realized income.
    pub by_strategy: Vec<(u32, f64)>,
}

impl Statement {
    pub fn net_realized(&self) -> f64 {
        self.spread_income + self.premium_recognized + self.service_income
            - self.costs
            - self.bond_opportunity_cost
    }
}

/// Replay the log into a statement. Pure and deterministic: same events,
/// same `now`, same rates ⇒ byte-identical statement on every client.
pub fn replay(events: &[Event], now: u64, vwap: f64, bond_rate_per_sec: f64) -> Statement {
    let mut s = Statement::default();
    let mut strategy_income: std::collections::BTreeMap<u32, f64> = Default::default();
    let mut bonds: Vec<(u64, f64)> = Vec::new(); // (lock time, amount)
    for e in events {
        match *e {
            Event::Fill { strategy, spread_xmr, .. } => {
                s.spread_income += spread_xmr;
                *strategy_income.entry(strategy).or_default() += spread_xmr;
            }
            Event::Premium { t, strategy, amount_xmr, duration } => {
                let elapsed = now.saturating_sub(t).min(duration.max(1));
                let recognized = amount_xmr * elapsed as f64 / duration.max(1) as f64;
                s.premium_recognized += recognized;
                s.premium_deferred += amount_xmr - recognized;
                *strategy_income.entry(strategy).or_default() += recognized;
            }
            Event::Service { amount_xmr, .. } => s.service_income += amount_xmr,
            Event::Cost { amount_xmr, .. } => s.costs += amount_xmr,
            Event::BondLock { t, amount_xmr } => bonds.push((t, amount_xmr)),
            Event::BondRelease { amount_xmr, .. } => {
                // Release oldest first.
                let mut remaining = amount_xmr;
                while remaining > 0.0 {
                    match bonds.first_mut() {
                        Some((_, a)) if *a <= remaining => {
                            remaining -= *a;
                            bonds.remove(0);
                        }
                        Some((_, a)) => {
                            *a -= remaining;
                            remaining = 0.0;
                        }
                        None => break,
                    }
                }
            }
            Event::InventoryDelta { xno, xmr, .. } => {
                s.inventory_xno += xno;
                s.inventory_xmr += xmr;
            }
        }
    }
    for (t, a) in &bonds {
        s.bond_opportunity_cost += a * bond_rate_per_sec * now.saturating_sub(*t) as f64;
    }
    s.unrealized_xmr_eq = s.inventory_xno * vwap;
    s.by_strategy = strategy_income.into_iter().collect();
    s
}
