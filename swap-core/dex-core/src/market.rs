//! B2/N6: market data from the settled-trade journal only.
//!
//! Candles, ticker, and volume are pure functions of settled trades (each
//! anchored on-chain per N1/N6). Quotes never move these numbers; a fake
//! candle is unprintable because every candle hashes to its constituent
//! trades. VWAP/volatility come from `swap-engine` (one implementation,
//! everywhere).

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

pub use swap_engine::premium::{volatility, vwap, SettledTrade};

use crate::order::Bytes32;

/// One OHLC candle with integrity hash.
#[derive(Clone, Debug, PartialEq)]
pub struct Candle {
    /// Bucket start (unix seconds, aligned to `interval`).
    pub start: u64,
    pub open: f64,
    pub high: f64,
    pub low: f64,
    pub close: f64,
    /// Base-asset volume settled inside the bucket.
    pub volume: f64,
    pub trade_count: usize,
    /// Blake2b over the constituent trades — the audit handle (B2).
    pub integrity: Bytes32,
}

/// Build candles from settled trades. Trades must carry block timestamps
/// (not local clocks); buckets with no trades are simply absent — an empty
/// market is shown empty. A zero `interval` is a caller bug and returns an
/// empty set rather than panicking.
pub fn candles(trades: &[SettledTrade], interval: u64) -> Vec<Candle> {
    if interval == 0 {
        return Vec::new();
    }
    let mut sorted: Vec<&SettledTrade> = trades.iter().collect();
    sorted.sort_by_key(|t| t.timestamp);
    let mut out: Vec<Candle> = Vec::new();
    for t in sorted {
        let start = t.timestamp - (t.timestamp % interval);
        match out.last_mut() {
            Some(c) if c.start == start => {
                c.high = c.high.max(t.price);
                c.low = c.low.min(t.price);
                c.close = t.price;
                c.volume += t.size;
                c.trade_count += 1;
                c.integrity = fold_integrity(&c.integrity, t);
            }
            _ => {
                let mut c = Candle {
                    start,
                    open: t.price,
                    high: t.price,
                    low: t.price,
                    close: t.price,
                    volume: t.size,
                    trade_count: 1,
                    integrity: [0u8; 32],
                };
                c.integrity = fold_integrity(&c.integrity, t);
                out.push(c);
            }
        }
    }
    out
}

fn fold_integrity(acc: &Bytes32, t: &SettledTrade) -> Bytes32 {
    let mut h = Blake2b::<U32>::new();
    h.update(acc);
    h.update(t.price.to_be_bytes());
    h.update(t.size.to_be_bytes());
    h.update(t.timestamp.to_be_bytes());
    h.finalize().into()
}

/// The honest ticker: decay VWAP, last price, and rolling volume over
/// `window` seconds — all from settled trades.
#[derive(Debug, PartialEq)]
pub struct Ticker {
    pub vwap: Option<f64>,
    pub last: Option<f64>,
    pub volume: f64,
}

pub fn ticker(trades: &[SettledTrade], now: u64, half_life: f64, window: u64) -> Ticker {
    let last = trades
        .iter()
        .max_by_key(|t| t.timestamp)
        .map(|t| t.price);
    let volume = trades
        .iter()
        .filter(|t| now.saturating_sub(t.timestamp) <= window)
        .map(|t| t.size)
        .sum();
    Ticker {
        vwap: vwap(trades, now, half_life),
        last,
        volume,
    }
}
