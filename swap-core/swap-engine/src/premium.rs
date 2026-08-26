//! I4/N6 pricing: the oracle-free reference price and the explicit option
//! premium.
//!
//! Inputs are settled trades only (each anchored on-chain per N1/N6); quotes
//! never move these numbers, so wash-quoting is worthless. All arithmetic is
//! f64 over raw ratios — display-layer material, never consensus material.

/// One settled trade: price (XMR per XNO, or any consistent quote), size in
/// raw units of the base asset, and its settlement timestamp (seconds).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SettledTrade {
    pub price: f64,
    pub size: f64,
    pub timestamp: u64,
}

/// Exponential-decay VWAP over settled trades: weight = size · 2^(−age/half_life).
/// Returns `None` with no trades (an empty market is shown empty — B2).
pub fn vwap(trades: &[SettledTrade], now: u64, half_life_secs: f64) -> Option<f64> {
    if !(half_life_secs > 0.0) {
        return None; // audit #19: no NaN weights on a zero/neg half-life
    }
    let mut num = 0.0;
    let mut den = 0.0;
    for t in trades {
        let age = now.saturating_sub(t.timestamp) as f64;
        let w = t.size * (-age / half_life_secs * std::f64::consts::LN_2).exp();
        num += w * t.price;
        den += w;
    }
    (den > 0.0).then(|| num / den)
}

/// Exponential-decay volatility: weighted standard deviation of log returns
/// between consecutive settled trades, annualized-free (per sqrt-second of
/// average inter-trade gap is deliberately NOT applied — the premium formula
/// consumes raw per-window volatility).
pub fn volatility(trades: &[SettledTrade], now: u64, half_life_secs: f64) -> Option<f64> {
    if trades.len() < 2 || !(half_life_secs > 0.0) {
        return None;
    }
    let mut sorted: Vec<&SettledTrade> = trades.iter().collect();
    sorted.sort_by_key(|t| t.timestamp);
    let mut wsum = 0.0;
    let mut mean_acc = 0.0;
    let mut sq_acc = 0.0;
    for pair in sorted.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        if a.price <= 0.0 || b.price <= 0.0 {
            continue;
        }
        let r = (b.price / a.price).ln();
        let age = now.saturating_sub(b.timestamp) as f64;
        let w = (-age / half_life_secs * std::f64::consts::LN_2).exp();
        wsum += w;
        mean_acc += w * r;
        sq_acc += w * r * r;
    }
    if wsum <= 0.0 {
        return None;
    }
    let mean = mean_acc / wsum;
    let var = (sq_acc / wsum - mean * mean).max(0.0);
    Some(var.sqrt())
}

/// The I4 option premium at quote time, as a fraction of trade value:
/// `base + k · volatility · sqrt(expected_duration / duration_unit)`,
/// decaying linearly to `base` as the swap progresses (`elapsed` toward
/// `expected_duration`). The matched counterparty holds a free option until
/// settlement; this prices it explicitly instead of hiding it in the spread.
#[derive(Clone, Copy, Debug)]
pub struct PremiumParams {
    /// Floor premium (covers fixed costs), e.g. 0.001 = 10 bps.
    pub base: f64,
    /// Volatility multiplier `k`.
    pub k: f64,
    /// Expected swap duration in seconds for the quoted size.
    pub expected_duration: f64,
    /// The window volatility was measured over, in seconds.
    pub duration_unit: f64,
}

pub fn premium(params: &PremiumParams, vol: f64, elapsed: f64) -> f64 {
    if !(params.duration_unit > 0.0) {
        return params.base; // audit #19: no inf scale on a zero duration_unit
    }
    let remaining = (params.expected_duration - elapsed).max(0.0);
    let time_factor = if params.expected_duration > 0.0 {
        remaining / params.expected_duration
    } else {
        0.0
    };
    let scale = (params.expected_duration / params.duration_unit).max(0.0).sqrt();
    params.base + params.k * vol * scale * time_factor
}
