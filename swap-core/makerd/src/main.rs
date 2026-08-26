//! `makerd` — an always-on automated maker (I6 liveness + I8 embedded bot).
//!
//! Connects to a relay's peer gossip port and continuously posts a fresh
//! ladder of signed buy/sell orders (own key, own funds model — no custody, no
//! pool). Re-gossips on an interval so the book stays live and fresh (short
//! expiries + auto-repost).
//!
//! The mid anchors to the relay's LIVE order book (`Book::mid`, best bid/ask)
//! once two-sided depth exists; before that it holds the operator-supplied
//! `--mid` reference. It never fabricates a price with a random walk — a maker
//! with no book to read quotes its operator's reference and waits. Orders carry
//! the maker's persistent verifying key (loaded from `MAKERD_KEY`) so takers
//! can find them.
//!
//! Taking an order (completing the actual atomic swap) runs the `swap-executor`
//! session: `swapper --role maker --listen <addr> --nano <url> ... --live` — the
//! maker-side settle (`run_bob`), which needs real XMR keys/funds and is run
//! under supervision, not by this order-posting bot.
//!
//! Usage: makerd <relay_host:port> [--mid <xmr_per_xno>] [--levels N]
//!               [--size <xno>] [--spread <bps>] [--interval <secs>]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dex_core::book::Book;
use dex_core::order::{OrderBody, Side, SignedOrder};
use dex_core::triggers::{order_for_fire, Action, Condition, Engine, OrderTemplate, Trigger};
use rand::rngs::OsRng;

const MSG_ORDER: u8 = 0x01;
const MAX_MSG: u32 = 1 << 20;

struct Config {
    relay: String,
    mid: f64,
    levels: usize,
    size_xno: f64,
    spread_bps: f64,
    interval: u64,
    /// Optional stop-limit: (stop_level, limit_rate, side, size_xno). When the
    /// mid crosses `stop_level`, the maker fires a limit order at `limit_rate`.
    /// Absent by default → the trigger engine is armed with nothing and the
    /// maker's laddering behavior is completely unchanged.
    stop_limit: Option<(f64, f64, Side, f64)>,
}

fn parse_args() -> Config {
    let mut a = std::env::args().skip(1);
    let relay = a.next().unwrap_or_else(|| {
        eprintln!("usage: makerd <relay_host:port> [--mid X --levels N --size X --spread bps --interval s]");
        std::process::exit(2);
    });
    let mut cfg = Config {
        relay,
        mid: 0.003750,
        levels: 6,
        size_xno: 100.0,
        spread_bps: 20.0,
        interval: 20,
        stop_limit: None,
    };
    let rest: Vec<String> = a.collect();
    let mut i = 0;
    while i + 1 < rest.len() {
        let v = &rest[i + 1];
        match rest[i].as_str() {
            "--mid" => cfg.mid = v.parse().unwrap_or(cfg.mid),
            "--levels" => cfg.levels = v.parse().unwrap_or(cfg.levels),
            "--size" => cfg.size_xno = v.parse().unwrap_or(cfg.size_xno),
            "--spread" => cfg.spread_bps = v.parse().unwrap_or(cfg.spread_bps),
            "--interval" => cfg.interval = v.parse().unwrap_or(cfg.interval),
            // --stop-limit stop:limit:side:size  (side = sellxno | sellxmr)
            "--stop-limit" => cfg.stop_limit = parse_stop_limit(v),
            _ => {}
        }
        i += 2;
    }
    cfg
}

fn parse_stop_limit(v: &str) -> Option<(f64, f64, Side, f64)> {
    let p: Vec<&str> = v.split(':').collect();
    if p.len() != 4 {
        return None;
    }
    let stop = p[0].parse().ok()?;
    let limit = p[1].parse().ok()?;
    let side = match p[2].to_ascii_lowercase().as_str() {
        "sellxno" => Side::SellXno,
        "sellxmr" => Side::SellXmr,
        _ => return None,
    };
    let size = p[3].parse().ok()?;
    Some((stop, limit, side, size))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Load the maker's signing key from `MAKERD_KEY` (64 hex chars = a 32-byte
/// scalar seed) or generate a fresh one and print its seed for persistence.
///
/// Audit #22: the maker identity must be PERSISTENT across restarts. A fresh
/// random key per run means every restart re-keys the maker — takers tracking
/// the maker, its FCFS receipts, and the PoF/reputation anchored to that key
/// all break, and orders from "the same" maker become unverifiable as such.
/// (There is no code here that ever loads a private key from disk beyond this
/// explicit, env-gated seed; the seed is only ever printed to stderr.)
fn load_or_create_key() -> signing::SigningKey {
    if let Ok(hex_seed) = std::env::var("MAKERD_KEY") {
        let hex_seed = hex_seed.trim();
        if let Ok(bytes) = hex::decode(hex_seed) {
            if let Ok(key) = signing::SigningKey::deserialize(&bytes) {
                return key;
            }
            eprintln!("makerd: MAKERD_KEY did not deserialize to a valid key; ignoring");
        } else {
            eprintln!("makerd: MAKERD_KEY is not valid hex; ignoring");
        }
    }
    let key = signing::SigningKey::new(&mut OsRng);
    eprintln!(
        "makerd: no MAKERD_KEY set — generated a fresh key. Persist it across restarts with:\n  MAKERD_KEY={}",
        hex::encode(key.serialize())
    );
    key
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut f = vec![MSG_ORDER];
    f.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Read one relay frame: tag + u32 length + payload (mirrors `dexd`).
fn read_frame(stream: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr)?;
    let len = u32::from_be_bytes(hdr[1..5].try_into().unwrap());
    if len > MAX_MSG {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "oversized"));
    }
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload)?;
    Ok((hdr[0], payload))
}

/// Sign one order with the persistent maker key.
fn sign_order(
    key: &signing::SigningKey,
    maker: [u8; 32],
    side: Side,
    amount_xno: f64,
    rate: f64,
    nonce: u64,
) -> SignedOrder {
    let body = OrderBody {
        maker,
        side,
        amount: (amount_xno * 1e30) as u128,
        rate_pico: (rate * 1e12) as u128,
        expiry: now() + 90, // short — refreshed each interval (M3 freshness)
        nonce,
        pof_hash: dex_core::order::NO_POF,
    };
    let sig = key.sign(OsRng, &body.encode());
    SignedOrder {
        body,
        signature: sig.serialize().unwrap().try_into().unwrap(),
    }
}

/// Sign an already-built order body (used by the stop-limit trigger path,
/// whose body comes from `dex_core::triggers::order_for_fire`).
fn sign_body(key: &signing::SigningKey, body: OrderBody) -> SignedOrder {
    let sig = key.sign(OsRng, &body.encode());
    SignedOrder {
        body,
        signature: sig.serialize().unwrap().try_into().unwrap(),
    }
}

fn main() {
    let cfg = parse_args();
    // Persistent maker identity (audit #22): loaded from MAKERD_KEY, else a
    // freshly-generated key whose seed is printed for the operator to persist.
    let key = load_or_create_key();
    let maker: [u8; 32] = signing::VerifyingKey::from(&key)
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    eprintln!(
        "makerd: maker={} relay={} mid={:.6} levels={} size={} spread={}bps interval={}s",
        hex::encode(&maker[..6]),
        cfg.relay,
        cfg.mid,
        cfg.levels,
        cfg.size_xno,
        cfg.spread_bps,
        cfg.interval
    );

    // The local trigger engine (B3): stop-limits are evaluated HERE, in the
    // maker's own process against its mid — never delegated to the relay. Armed
    // only if --stop-limit was given; otherwise it holds nothing and every
    // step() is a no-op, leaving the laddering behavior below unchanged.
    let mut engine = Engine::default();
    let template: Option<OrderTemplate> = cfg.stop_limit.map(|(stop, limit, side, size)| {
        engine.arm(Trigger::new(
            1,
            Condition::StopBelow { level: stop },
            Action::FireLimit { rate: limit },
            u64::MAX,
            None,
        ));
        eprintln!("makerd: armed stop-limit stop={stop:.6} limit={limit:.6} side={side:?} size={size}");
        OrderTemplate {
            maker,
            side,
            amount: (size * 1e30) as u128,
            ttl: 90,
            pof_hash: dex_core::order::NO_POF,
        }
    });

    let mut mid = cfg.mid;
    let mut nonce: u64 = now();

    // A persistent reader connection ingests the relay's gossip (plus the
    // join snapshot) into a local book, from which we derive the anchor mid.
    let book: Arc<Mutex<Book>> = Arc::new(Mutex::new(Book::default()));
    loop {
        match TcpStream::connect(&cfg.relay) {
            Ok(reader) => {
                let rbook = book.clone();
                thread::spawn(move || {
                    let mut reader = reader;
                    loop {
                        match read_frame(&mut reader) {
                            Ok((MSG_ORDER, payload)) => {
                                if let Some(o) = SignedOrder::from_wire(&payload) {
                                    rbook.lock().unwrap().insert(o, now(), false);
                                }
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                });
                break;
            }
            Err(e) => {
                eprintln!("makerd: relay {} unreachable: {e} — retrying", cfg.relay);
                thread::sleep(Duration::from_secs(cfg.interval));
            }
        }
    }

    loop {
        // Anchor mid to the live book when it has two-sided depth; otherwise
        // hold the operator's `--mid` reference. No fabricated random walk.
        // Sweep expired orders first so dead depth can't pin a stale mid.
        {
            let mut b = book.lock().unwrap();
            b.sweep_expired(now());
            if let Some(book_mid) = b.mid() {
                mid = book_mid;
            }
        }

        match TcpStream::connect(&cfg.relay) {
            Ok(mut stream) => {
                let half = cfg.spread_bps / 10_000.0;
                let mut posted = 0;
                for l in 0..cfg.levels {
                    let step = half * (1.0 + l as f64);
                    // sell XNO above mid (ask), buy XNO below mid (bid = sell XMR).
                    let ask = sign_order(
                        &key,
                        maker,
                        Side::SellXno,
                        cfg.size_xno,
                        mid * (1.0 + step),
                        nonce,
                    );
                    nonce += 1;
                    let bid = sign_order(
                        &key,
                        maker,
                        Side::SellXmr,
                        cfg.size_xno,
                        mid * (1.0 - step),
                        nonce,
                    );
                    nonce += 1;
                    if stream.write_all(&frame(&ask.to_wire())).is_ok() {
                        posted += 1;
                    }
                    if stream.write_all(&frame(&bid.to_wire())).is_ok() {
                        posted += 1;
                    }
                }
                // Evaluate the stop-limit against the current mid. On a cross it
                // fires once, and its limit order is signed and gossiped on the
                // same stream (the trigger→signed-order wiring).
                if let Some(tmpl) = &template {
                    if let Some(fired) = engine.step(mid, now()) {
                        let body = order_for_fire(fired.action, tmpl, mid, now(), nonce);
                        nonce += 1;
                        let so = sign_body(&key, body);
                        if stream.write_all(&frame(&so.to_wire())).is_ok() {
                            posted += 1;
                            eprintln!("makerd: STOP-LIMIT fired (id {}) → posted limit @ mid {mid:.6}", fired.id);
                        }
                    }
                }
                let _ = stream.flush();
                eprintln!("makerd: posted {posted} orders around mid {mid:.6}");
            }
            Err(e) => eprintln!("makerd: relay {} unreachable: {e}", cfg.relay),
        }
        thread::sleep(Duration::from_secs(cfg.interval));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wired stop-limit path: parse config → arm the engine → mid crosses
    /// the stop → order_for_fire builds the limit order → sign → it verifies.
    #[test]
    fn stop_limit_wiring_fires_a_valid_signed_order() {
        // Config parsing.
        let (stop, limit, side, size) = parse_stop_limit("0.0034:0.0032:sellxno:250").unwrap();
        assert_eq!(side, Side::SellXno);
        assert!((limit - 0.0032).abs() < 1e-12);
        assert!(parse_stop_limit("garbage").is_none());
        assert!(parse_stop_limit("1:2:badside:3").is_none());

        // Arm + evaluate.
        let key = signing::SigningKey::new(&mut OsRng);
        let maker: [u8; 32] = signing::VerifyingKey::from(&key)
            .serialize().unwrap().try_into().unwrap();
        let mut engine = Engine::default();
        engine.arm(Trigger::new(
            1, Condition::StopBelow { level: stop }, Action::FireLimit { rate: limit }, u64::MAX, None,
        ));
        let tmpl = OrderTemplate { maker, side, amount: (size * 1e30) as u128, ttl: 90, pof_hash: dex_core::order::NO_POF };

        assert!(engine.step(0.0036, 100).is_none(), "above stop: no fire");
        let fired = engine.step(0.0033, 101).expect("mid crossed the stop");

        // Wire → sign → verify. The order carries the LIMIT price, not the stop.
        let body = order_for_fire(fired.action, &tmpl, 0.0035, 101, 7);
        assert_eq!(body.rate_pico, (limit * 1e12) as u128);
        assert_eq!(body.side, Side::SellXno);
        let so = sign_body(&key, body);
        assert!(so.verify(101), "fired stop-limit produces a broadcastable signed order");
    }
}
