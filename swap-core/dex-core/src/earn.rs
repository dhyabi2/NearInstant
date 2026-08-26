//! G1: the quoting engine behind the Earn toggle.
//!
//! Own funds, own keys, no pool. Quotes anchor to the settled-trade VWAP
//! with spreads that widen with volatility, staleness, and thin depth;
//! inventory skew leans prices to shed excess exposure (G4); a drawdown
//! circuit breaker pauses quoting at the user's loss line. The projected
//! return is a REALIZED band computed from the user's own history — this
//! module has no code path that fabricates a forward APY.

/// User risk limits, set before the toggle turns on.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Base half-spread as a fraction (e.g. 0.002).
    pub half_spread: f64,
    /// Additional half-spread per unit of volatility.
    pub vol_widening: f64,
    /// Max acceptable inventory imbalance, as a fraction of total capital
    /// (0.5 = perfectly balanced target with ±this tolerance).
    pub max_skew: f64,
    /// Price lean per unit of skew (shed pressure).
    pub skew_lean: f64,
    /// Pause quoting when session drawdown reaches this fraction of capital.
    pub max_drawdown: f64,
    /// Pull quotes entirely when volatility exceeds this.
    pub vol_pull: f64,
}

/// Current portfolio snapshot in common units (XMR-equivalent at VWAP).
#[derive(Clone, Copy, Debug)]
pub struct Inventory {
    pub xno_value: f64,
    pub xmr_value: f64,
}

impl Inventory {
    pub fn total(&self) -> f64 {
        self.xno_value + self.xmr_value
    }
    /// Signed skew: positive = XNO-heavy.
    pub fn skew(&self) -> f64 {
        let t = self.total();
        if t <= 0.0 {
            return 0.0;
        }
        (self.xno_value - self.xmr_value) / t
    }
}

/// The engine's decision for this tick.
#[derive(Debug, PartialEq)]
pub enum Quotes {
    /// Two-sided quotes (rates in XMR per XNO).
    TwoSided { bid: f64, ask: f64 },
    /// One side pulled to shed inventory faster.
    Skewed { bid: Option<f64>, ask: Option<f64> },
    /// Everything pulled: volatility spike or breaker tripped, with reason.
    Pulled(&'static str),
}

/// Session breaker state.
#[derive(Debug, Default)]
pub struct Breaker {
    pub session_start_value: f64,
    pub tripped: bool,
}

impl Breaker {
    pub fn new(start_value: f64) -> Self {
        Self {
            session_start_value: start_value,
            tripped: false,
        }
    }
    /// Update with the current marked value; trips (latching) past the line.
    pub fn update(&mut self, current_value: f64, max_drawdown: f64) -> bool {
        if self.session_start_value > 0.0 {
            let dd = (self.session_start_value - current_value) / self.session_start_value;
            if dd >= max_drawdown {
                self.tripped = true;
            }
        }
        self.tripped
    }
}

/// Produce this tick's quotes.
pub fn quote(
    vwap: f64,
    vol: f64,
    inv: &Inventory,
    limits: &Limits,
    breaker: &Breaker,
) -> Quotes {
    if breaker.tripped {
        return Quotes::Pulled("drawdown breaker");
    }
    if vol >= limits.vol_pull {
        return Quotes::Pulled("volatility spike");
    }
    let half = limits.half_spread + limits.vol_widening * vol;
    let lean = -inv.skew() * limits.skew_lean; // XNO-heavy ⇒ lean price down to sell XNO
    let mid = vwap * (1.0 + lean);
    let bid = mid * (1.0 - half);
    let ask = mid * (1.0 + half);
    let skew = inv.skew();
    if skew.abs() > limits.max_skew {
        // Quote only the side that sheds the excess.
        if skew > 0.0 {
            // XNO-heavy: only offer to SELL XNO (taker buys XNO at our ask).
            Quotes::Skewed { bid: None, ask: Some(ask) }
        } else {
            Quotes::Skewed { bid: Some(bid), ask: None }
        }
    } else {
        Quotes::TwoSided { bid, ask }
    }
}

/// The single coin a *native* LP holds and returns to. This is option 1:
/// a provider who owns ONLY Nano (or ONLY Monero) earns the swap spread while
/// keeping (almost) all value in its native coin. It NEVER converts its own
/// funds — every coin movement is a taker-driven atomic swap, so the taker
/// pays the Monero fee. It holds the OTHER coin only *transiently*, between a
/// draining fill and the restoring fill that returns it to native. Two native
/// LPs on opposite coins are counterparties by emergence: the order book pairs
/// takers to whichever side has inventory. No joint escrow, no new crypto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Native {
    Xno,
    Xmr,
}

impl Native {
    /// This LP's native-coin value as a fraction of total (1.0 = fully native).
    fn frac(self, inv: &Inventory) -> f64 {
        let t = inv.total();
        if t <= 0.0 {
            return 1.0;
        }
        match self {
            Native::Xno => inv.xno_value / t,
            Native::Xmr => inv.xmr_value / t,
        }
    }
}

/// Quote for a single-coin native LP (option 1). Targets ~fully-native, holding
/// only a small `working` band of non-native inventory at equilibrium; leans
/// price to pull inventory back toward native; and — the key rule — PAUSES the
/// draining side once native inventory falls to `native_floor`, so the LP can
/// never be emptied out of its native coin by one-directional flow. The
/// draining side is the one that sells the native coin (for XNO: the ask, a
/// taker buying XNO from us); the restoring side buys it back.
///
/// `working` is the non-native fraction the LP is willing to hold to keep the
/// restoring side quotable (reuse `Limits.max_skew`); `native_floor` is the
/// hard native reserve (must be > 1 − 1, i.e. between the equilibrium and 1).
pub fn quote_native(
    vwap: f64,
    vol: f64,
    inv: &Inventory,
    native: Native,
    limits: &Limits,
    working: f64,
    native_floor: f64,
    breaker: &Breaker,
) -> Quotes {
    if breaker.tripped {
        return Quotes::Pulled("drawdown breaker");
    }
    if vol >= limits.vol_pull {
        return Quotes::Pulled("volatility spike");
    }
    let half = limits.half_spread + limits.vol_widening * vol;
    let native_frac = native.frac(inv);
    // Equilibrium target: hold `working` in the non-native coin, the rest native.
    let target_native = (1.0 - working).clamp(native_floor, 1.0);
    let shortfall = target_native - native_frac; // >0 ⇒ too little native ⇒ restore
    // Lean the mid to pull back toward native. For XNO-native a native shortfall
    // means we want to BUY XNO, so we raise the price (attract XNO sellers);
    // for XMR-native the sign flips. When over-native (shortfall<0) the same
    // expression leans the other way to start shedding into the spread.
    let sign = match native {
        Native::Xno => 1.0,
        Native::Xmr => -1.0,
    };
    let lean = sign * shortfall * limits.skew_lean;
    let mid = vwap * (1.0 + lean);
    let bid = mid * (1.0 - half);
    let ask = mid * (1.0 + half);
    // Map draining/restoring to concrete sides.
    //  XNO-native: ask = sell XNO = DRAIN native; bid = buy XNO = RESTORE.
    //  XMR-native: bid = buy XNO (spend XMR) = DRAIN native; ask = RESTORE.
    let (drain, restore) = match native {
        Native::Xno => (ask, bid),
        Native::Xmr => (bid, ask),
    };
    let at_floor = native_frac <= native_floor;
    let no_working = native_frac >= 1.0 - 1e-9; // nothing non-native to trade back
    let side = |drain_on: bool, restore_on: bool| -> Quotes {
        // Re-assemble bid/ask from which logical sides are live.
        let (bid_on, ask_on) = match native {
            Native::Xno => (restore_on, drain_on),
            Native::Xmr => (drain_on, restore_on),
        };
        match (bid_on, ask_on) {
            (true, true) => Quotes::TwoSided { bid, ask },
            (b, a) => Quotes::Skewed {
                bid: if b { Some(bid) } else { None },
                ask: if a { Some(ask) } else { None },
            },
        }
    };
    let _ = (drain, restore); // documented aliases; concrete prices are bid/ask
    if at_floor {
        // Native reserve hit: stop draining, only restore.
        side(false, true)
    } else if no_working {
        // Fully native: nothing to sell back, only offer the draining side so
        // the LP can start earning the spread.
        side(true, false)
    } else {
        side(true, true)
    }
}

/// The honest pre-commit projection: the REALIZED per-capital return band of
/// the user's own last `window`-seconds of fills, or `None` when there is no
/// history (shown as "no data", never a promise).
pub fn realized_band(
    fills: &[(u64, f64)], // (timestamp, net income in XMR-eq)
    capital: f64,
    now: u64,
    window: u64,
) -> Option<(f64, f64)> {
    if capital <= 0.0 {
        return None;
    }
    let recent: Vec<f64> = fills
        .iter()
        .filter(|(t, _)| now.saturating_sub(*t) <= window)
        .map(|(_, v)| *v / capital)
        .collect();
    if recent.len() < 3 {
        return None;
    }
    let total: f64 = recent.iter().sum();
    let mean = total / recent.len() as f64;
    let var = recent.iter().map(|r| (r - mean) * (r - mean)).sum::<f64>() / recent.len() as f64;
    let sd = var.sqrt() * recent.len() as f64;
    Some(((total - sd).max(0.0), total + sd))
}

#[cfg(test)]
mod native_tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            half_spread: 0.002,
            vol_widening: 0.0,
            max_skew: 0.2,
            skew_lean: 0.01,
            max_drawdown: 0.2,
            vol_pull: 1.0,
        }
    }

    // A Nano-only LP that is fully in XNO offers ONLY the draining side (sell
    // XNO), so it can begin earning; it has no XMR yet to quote the buy-back.
    #[test]
    fn xno_native_fully_native_offers_only_drain() {
        let inv = Inventory { xno_value: 100.0, xmr_value: 0.0 };
        let q = quote_native(1.0, 0.0, &inv, Native::Xno, &limits(), 0.2, 0.5, &Breaker::default());
        match q {
            Quotes::Skewed { bid, ask } => {
                assert!(bid.is_none(), "no buy-back with zero XMR inventory");
                assert!(ask.is_some(), "must offer to sell XNO to start earning");
            }
            other => panic!("expected drain-only, got {other:?}"),
        }
    }

    // Once it holds a working XMR balance (still XNO-heavy, above floor), it
    // quotes BOTH sides and earns the round-trip spread.
    #[test]
    fn xno_native_in_band_is_two_sided() {
        let inv = Inventory { xno_value: 80.0, xmr_value: 20.0 };
        let q = quote_native(1.0, 0.0, &inv, Native::Xno, &limits(), 0.2, 0.5, &Breaker::default());
        match q {
            Quotes::TwoSided { bid, ask } => assert!(ask > bid, "ask above bid = positive spread"),
            other => panic!("expected two-sided, got {other:?}"),
        }
    }

    // One-directional flow drains native below the floor: the draining side is
    // PAUSED so the Nano-only LP can never be emptied of XNO; only the restoring
    // (buy XNO back) side stays live.
    #[test]
    fn xno_native_at_floor_pauses_drain() {
        let inv = Inventory { xno_value: 40.0, xmr_value: 60.0 }; // 40% native < 50% floor
        let q = quote_native(1.0, 0.0, &inv, Native::Xno, &limits(), 0.2, 0.5, &Breaker::default());
        match q {
            Quotes::Skewed { bid, ask } => {
                assert!(ask.is_none(), "draining side (sell XNO) paused at the floor");
                assert!(bid.is_some(), "restore side (buy XNO back) stays live");
            }
            other => panic!("expected restore-only, got {other:?}"),
        }
    }

    // The XMR-only LP is the exact mirror: fully in XMR, it offers only its
    // draining side (buy XNO with XMR), which is the bid.
    #[test]
    fn xmr_native_fully_native_offers_only_drain() {
        let inv = Inventory { xno_value: 0.0, xmr_value: 100.0 };
        let q = quote_native(1.0, 0.0, &inv, Native::Xmr, &limits(), 0.2, 0.5, &Breaker::default());
        match q {
            Quotes::Skewed { bid, ask } => {
                assert!(ask.is_none(), "XMR-native has no XNO to sell back yet");
                assert!(bid.is_some(), "must offer to buy XNO (spend XMR) to start earning");
            }
            other => panic!("expected drain-only, got {other:?}"),
        }
    }

    // Native LP leans price to pull inventory back toward native: below target,
    // a Nano-only LP raises its mid to attract XNO sellers (restore).
    #[test]
    fn xno_native_leans_up_when_below_target() {
        let low = Inventory { xno_value: 55.0, xmr_value: 45.0 };  // below target native
        let high = Inventory { xno_value: 95.0, xmr_value: 5.0 };  // above target native
        let ql = quote_native(1.0, 0.0, &low, Native::Xno, &limits(), 0.2, 0.4, &Breaker::default());
        let qh = quote_native(1.0, 0.0, &high, Native::Xno, &limits(), 0.2, 0.4, &Breaker::default());
        let mid = |q: &Quotes| match q {
            Quotes::TwoSided { bid, ask } => (bid + ask) / 2.0,
            Quotes::Skewed { bid, ask } => bid.or(*ask).unwrap(),
            _ => panic!("pulled"),
        };
        assert!(mid(&ql) > mid(&qh), "leans mid UP when native-short to attract restoring flow");
    }

    // Breaker and volatility pulls still apply to native quoting.
    #[test]
    fn native_respects_breaker_and_vol() {
        let inv = Inventory { xno_value: 80.0, xmr_value: 20.0 };
        let mut b = Breaker::new(100.0);
        b.update(50.0, 0.2);
        assert!(matches!(
            quote_native(1.0, 0.0, &inv, Native::Xno, &limits(), 0.2, 0.5, &b),
            Quotes::Pulled(_)
        ));
        let l = Limits { vol_pull: 0.1, ..limits() };
        assert!(matches!(
            quote_native(1.0, 0.5, &inv, Native::Xno, &l, 0.2, 0.5, &Breaker::default()),
            Quotes::Pulled(_)
        ));
    }
}
