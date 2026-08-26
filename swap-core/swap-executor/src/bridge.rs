//! Local wallet-bridge RPC — the seed of "the browser is not a demo" path.
//!
//! A non-technical user should never paste keys into a web page. Instead a tiny
//! local helper (the `swapper` binary, `--serve`) holds the keys and the Monero
//! wallet and exposes a minimal JSON-RPC over a **localhost-only** WebSocket.
//! The browser is a thin, plain-English UI: it never touches key material; it
//! asks the local wallet to do the chain work.
//!
//! This module is the pure request dispatcher — a JSON string in, a JSON string
//! out, no networking — so it is unit-testable offline. `swapper --serve` wraps
//! it in a loopback socket, a same-origin check, and a one-time pairing token.
//!
//! Ops today (`check_reserve` = the take-time XMR proof-of-funds gate). The
//! full `run_alice`/`run_bob` session triggering rides the same channel as a
//! later slice; the dispatcher is intentionally additive.

use serde_json::{json, Value};

use crate::driver::XmrSide;

/// Dispatch one JSON-RPC request against the caller's XMR side.
pub fn handle_rpc(xmr: &dyn XmrSide, req: &str) -> String {
    let v: Value = match serde_json::from_str(req) {
        Ok(v) => v,
        Err(_) => return error("bad json"),
    };
    let op = v.get("op").and_then(|o| o.as_str()).unwrap_or("").to_string();
    match op.as_str() {
        "ping" => ok(json!({ "pong": true })),
        "xmr_address" => match xmr.xmr_address() {
            Ok(Some(a)) => ok(json!({ "address": a })),
            Ok(None) => ok(json!({ "address": null })),
            Err(e) => error(&format!("{e:?}")),
        },
        "xmr_balance" => match xmr.xmr_balance() {
            Ok(Some(b)) => ok(json!({ "balance": b.to_string() })),
            Ok(None) => ok(json!({ "balance": null })),
            Err(e) => error(&format!("{e:?}")),
        },
        "check_reserve" => {
            let address = v.get("address").and_then(|s| s.as_str()).unwrap_or("");
            let message = v.get("message").and_then(|s| s.as_str()).unwrap_or("");
            let signature = v.get("signature").and_then(|s| s.as_str()).unwrap_or("");
            match xmr.check_reserve(address, message, signature) {
                // Authoritative: funded/insufficient is decided by the caller
                // comparing `available` to the order amount.
                Ok(Some(s)) => ok(json!({ "status": {
                    "good": s.good,
                    "spent": s.spent.to_string(),
                    "total": s.total.to_string(),
                    "available": s.available().to_string(),
                }})),
                // No wallet to check → unverifiable, never a false pass.
                Ok(None) => ok(json!({ "status": null })),
                Err(e) => error(&format!("{e:?}")),
            }
        }
        _ => error("unknown op"),
    }
}

fn ok(result: Value) -> String {
    json!({ "ok": true, "result": result }).to_string()
}
fn error(msg: &str) -> String {
    json!({ "ok": false, "error": msg }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{ReserveStatus, XmrError};
    use crate::monero::JointXmr;
    use nano_ceremony::Bytes32;

    struct Mock(Option<Result<Option<ReserveStatus>, XmrError>>);

    impl XmrSide for Mock {
        fn lock(&self, _: &JointXmr, _: u128) -> Result<(), XmrError> {
            Ok(())
        }
        fn lock_matured(&self, _: &JointXmr) -> Result<bool, XmrError> {
            Ok(true)
        }
        fn sweep(&self, _: &JointXmr, _: &Bytes32) -> Result<(), XmrError> {
            Ok(())
        }
        fn check_reserve(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Option<ReserveStatus>, XmrError> {
            self.0.clone().unwrap_or(Ok(None))
        }
        fn xmr_address(&self) -> Result<Option<String>, XmrError> {
            Ok(Some("4fundme".into()))
        }
        fn xmr_balance(&self) -> Result<Option<u128>, XmrError> {
            Ok(Some(12_000_000_000_u128))
        }
    }

    #[test]
    fn ping_ok() {
        let m = Mock(None);
        let out: Value = serde_json::from_str(&handle_rpc(&m, r#"{"op":"ping"}"#)).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["result"]["pong"], true);
    }

    #[test]
    fn xmr_address_and_balance() {
        let m = Mock(None);
        let addr: Value =
            serde_json::from_str(&handle_rpc(&m, r#"{"op":"xmr_address"}"#)).unwrap();
        assert_eq!(addr["result"]["address"], "4fundme");
        let bal: Value = serde_json::from_str(&handle_rpc(&m, r#"{"op":"xmr_balance"}"#)).unwrap();
        assert_eq!(bal["result"]["balance"], "12000000000");
    }

    #[test]
    fn check_reserve_returns_status() {
        let m = Mock(Some(Ok(Some(ReserveStatus { good: true, spent: 10, total: 100 }))));
        let out: Value = serde_json::from_str(&handle_rpc(
            &m,
            r#"{"op":"check_reserve","address":"a","message":"m","signature":"s"}"#,
        ))
        .unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["result"]["status"]["good"], true);
        assert_eq!(out["result"]["status"]["available"], "90");
    }

    #[test]
    fn check_reserve_unverifiable_is_null_not_false() {
        let m = Mock(Some(Ok(None)));
        let out: Value = serde_json::from_str(&handle_rpc(
            &m,
            r#"{"op":"check_reserve","address":"a","message":"m","signature":"s"}"#,
        ))
        .unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["result"]["status"], Value::Null);
    }

    #[test]
    fn check_reserve_failure_is_fail_closed() {
        let m = Mock(Some(Err(XmrError::Lock("wallet down".into()))));
        let out: Value = serde_json::from_str(&handle_rpc(
            &m,
            r#"{"op":"check_reserve","address":"a","message":"m","signature":"s"}"#,
        ))
        .unwrap();
        assert_eq!(out["ok"], false);
        assert!(!out["error"].as_str().unwrap().is_empty());
    }

    #[test]
    fn rejects_bad_json_and_unknown_ops() {
        let m = Mock(None);
        assert_eq!(serde_json::from_str::<Value>(&handle_rpc(&m, "not json")).unwrap()["ok"], false);
        assert_eq!(serde_json::from_str::<Value>(&handle_rpc(&m, r#"{"op":"evil"}"#)).unwrap()["ok"], false);
    }
}