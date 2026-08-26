//! `MailboxWire` (R20) — the interactive ceremony over a swappable, fund-less,
//! censorship-resistant message relay, implementing the existing [`Wire`] trait
//! with ZERO change to the FROST/adaptor ceremonies that run on top.
//!
//! A browser cannot accept inbound sockets, so two strangers need a rendezvous
//! for the multi-round ceremony. The honest floor (see the R20 analysis) is a
//! DUMB store-and-forward relay that:
//!
//! - carries only end-to-end-encrypted, authenticated blobs (AES-256-GCM under
//!   a key derived from the swap's shared secret) — it can neither read, alter,
//!   reorder, nor inject a message without the receiver detecting it. AES-GCM +
//!   SHA-256 are chosen so a BROWSER client can interoperate using only the
//!   native WebCrypto `crypto.subtle` (no ChaCha/Blake2 shim) — see
//!   `web/mailbox.js`, which speaks this exact wire format;
//! - is addressed by a per-swap MAILBOX id + monotone SEQ, both bound into the
//!   AEAD associated data, so a swapped recipient or a replayed/reordered frame
//!   fails authentication;
//! - is FUNGIBLE: every message is broadcast to N independent relays and each
//!   read polls them all, so censoring or dropping one relay stops nothing.
//!
//! The relay never touches funds and holds no keys; trust in it is for
//! AVAILABILITY only. This is the transport that makes a frontend-only,
//! hard-to-censor ceremony possible without the native TCP wire.

use std::cell::Cell;
use std::io::Read as _;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};

use crate::{Wire, WireError};

/// SHA-256 of the concatenation of `parts` — the one hash both the native and
/// browser (WebCrypto) sides can compute identically.
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// A dumb store-and-forward relay: store an opaque blob at `(mailbox, seq)` and
/// return it on request. It sees only ciphertext and cannot alter it
/// undetectably. Implemented over HTTP for production, in-memory for tests.
pub trait Relay: Send + Sync {
    /// Store `blob` at `(mailbox, seq)`. Idempotent: re-posting the same slot is
    /// fine (broadcast retries).
    fn post(&self, mailbox: &str, seq: u64, blob: &[u8]) -> Result<(), String>;
    /// Fetch the blob at `(mailbox, seq)`, or `None` if not present yet.
    fn fetch(&self, mailbox: &str, seq: u64) -> Result<Option<Vec<u8>>, String>;
}

/// A [`Relay`] over a plain HTTP dumb store: `POST {base}/m/{mailbox}/{seq}`
/// stores the blob body; `GET {base}/m/{mailbox}/{seq}` returns it (404 = not
/// posted yet). Any commodity object store or a ~30-line server implements
/// this; run several and pass them all to a [`MailboxWire`] so no single one is
/// required. The server needs no logic beyond keyed put/get — it never sees
/// plaintext or keys.
pub struct HttpRelay {
    base: String,
    agent: ureq::Agent,
}

impl HttpRelay {
    pub fn new(base: impl Into<String>) -> Self {
        let base = base.into();
        let base = base.strip_suffix('/').map(str::to_string).unwrap_or(base);
        Self {
            base,
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(15))
                .build(),
        }
    }

    fn url(&self, mailbox: &str, seq: u64) -> String {
        format!("{}/m/{mailbox}/{seq}", self.base)
    }
}

impl Relay for HttpRelay {
    fn post(&self, mailbox: &str, seq: u64, blob: &[u8]) -> Result<(), String> {
        self.agent
            .post(&self.url(mailbox, seq))
            .set("Content-Type", "application/octet-stream")
            .send_bytes(blob)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn fetch(&self, mailbox: &str, seq: u64) -> Result<Option<Vec<u8>>, String> {
        match self.agent.get(&self.url(mailbox, seq)).call() {
            Ok(resp) => {
                let mut buf = Vec::new();
                resp.into_reader()
                    .read_to_end(&mut buf)
                    .map_err(|e| e.to_string())?;
                Ok(Some(buf))
            }
            // 404 = not posted yet (normal); other errors bubble up so the
            // caller can rotate relays.
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Derive the two directional mailbox ids and the shared AEAD key from a swap's
/// shared secret (e.g. the R18 rendezvous seed). Both parties call this with the
/// SAME `shared` and opposite `i_am_initiator` to get mirrored send/recv boxes.
pub fn derive(shared: &[u8; 32], i_am_initiator: bool) -> (String, String, [u8; 32]) {
    let mb = |label: &[u8]| -> String {
        hex::encode(sha256(&[b"xnoxmr-mailbox-id-v1", label, shared]))
    };
    let box_a = mb(b"A"); // initiator's outbox / responder's inbox
    let box_b = mb(b"B"); // responder's outbox / initiator's inbox
    let key: [u8; 32] = sha256(&[b"xnoxmr-mailbox-key-v1", shared]);
    if i_am_initiator {
        (box_a, box_b, key) // send on A, recv on B
    } else {
        (box_b, box_a, key) // send on B, recv on A
    }
}

/// A [`Wire`] that ships each message as an AEAD blob through one or more dumb
/// relays. `send` broadcasts to all relays; `recv` polls them all until the
/// next expected `(recv_mailbox, seq)` appears (up to `poll_timeout`).
pub struct MailboxWire {
    relays: Vec<Box<dyn Relay>>,
    cipher: Aes256Gcm,
    send_mailbox: String,
    recv_mailbox: String,
    send_seq: Cell<u64>,
    recv_seq: Cell<u64>,
    poll_every: Duration,
    poll_timeout: Duration,
}

impl MailboxWire {
    /// Build a wire from N relays, the derived mailbox pair, and the shared key.
    pub fn new(
        relays: Vec<Box<dyn Relay>>,
        send_mailbox: String,
        recv_mailbox: String,
        key: [u8; 32],
    ) -> Self {
        Self {
            relays,
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key)),
            send_mailbox,
            recv_mailbox,
            send_seq: Cell::new(0),
            recv_seq: Cell::new(0),
            poll_every: Duration::from_millis(500),
            poll_timeout: Duration::from_secs(120),
        }
    }

    /// Override the poll cadence/timeout (tests use a short timeout).
    pub fn with_polling(mut self, every: Duration, timeout: Duration) -> Self {
        self.poll_every = every;
        self.poll_timeout = timeout;
        self
    }

    /// Nonce for `(mailbox, seq)` — deterministic, unique per slot (the key is
    /// per-swap, so a 96-bit nonce derived from the mailbox+seq never repeats
    /// within a swap). Bound into the AEAD AAD as well.
    fn slot_nonce(mailbox: &str, seq: u64) -> [u8; 12] {
        let d = sha256(&[b"xnoxmr-mailbox-nonce-v1", mailbox.as_bytes(), &seq.to_le_bytes()]);
        d[..12].try_into().unwrap()
    }

    fn aad(mailbox: &str, seq: u64) -> Vec<u8> {
        let mut a = Vec::with_capacity(mailbox.len() + 8);
        a.extend_from_slice(mailbox.as_bytes());
        a.extend_from_slice(&seq.to_le_bytes());
        a
    }
}

impl Wire for MailboxWire {
    fn send(&self, msg: Vec<u8>) -> Result<(), WireError> {
        let seq = self.send_seq.get();
        let nonce = Self::slot_nonce(&self.send_mailbox, seq);
        let aad = Self::aad(&self.send_mailbox, seq);
        let blob = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &msg, aad: &aad })
            .map_err(|_| WireError::Malformed)?;
        // Broadcast to every relay; success if ANY accepts (the rest are
        // anti-censorship redundancy).
        let mut ok = false;
        for r in &self.relays {
            if r.post(&self.send_mailbox, seq, &blob).is_ok() {
                ok = true;
            }
        }
        if !ok {
            return Err(WireError::Closed);
        }
        self.send_seq.set(seq + 1);
        Ok(())
    }

    fn recv(&self) -> Result<Vec<u8>, WireError> {
        let seq = self.recv_seq.get();
        let nonce = Self::slot_nonce(&self.recv_mailbox, seq);
        let aad = Self::aad(&self.recv_mailbox, seq);
        let deadline = Instant::now() + self.poll_timeout;
        loop {
            for r in &self.relays {
                if let Ok(Some(blob)) = r.fetch(&self.recv_mailbox, seq) {
                    // AEAD verifies integrity + binds mailbox+seq: a tampered,
                    // reordered, or misrouted blob fails to decrypt.
                    let msg = self
                        .cipher
                        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &blob, aad: &aad })
                        .map_err(|_| WireError::BadContribution)?;
                    self.recv_seq.set(seq + 1);
                    return Ok(msg);
                }
            }
            if Instant::now() >= deadline {
                return Err(WireError::Closed);
            }
            std::thread::sleep(self.poll_every);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory relay shared between the two test wires.
    #[derive(Default)]
    struct MemRelay {
        store: Mutex<HashMap<(String, u64), Vec<u8>>>,
    }
    impl Relay for MemRelay {
        fn post(&self, mailbox: &str, seq: u64, blob: &[u8]) -> Result<(), String> {
            self.store.lock().unwrap().insert((mailbox.to_string(), seq), blob.to_vec());
            Ok(())
        }
        fn fetch(&self, mailbox: &str, seq: u64) -> Result<Option<Vec<u8>>, String> {
            Ok(self.store.lock().unwrap().get(&(mailbox.to_string(), seq)).cloned())
        }
    }

    // A relay that DROPS every post (a censoring/dead relay).
    struct DeadRelay;
    impl Relay for DeadRelay {
        fn post(&self, _: &str, _: u64, _: &[u8]) -> Result<(), String> {
            Err("censored".into())
        }
        fn fetch(&self, _: &str, _: u64) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
    }

    fn wires(shared: &[u8; 32]) -> (MailboxWire, MailboxWire, std::sync::Arc<MemRelay>) {
        let relay = std::sync::Arc::new(MemRelay::default());
        let (a_send, a_recv, key) = derive(shared, true);
        let (b_send, b_recv, key2) = derive(shared, false);
        assert_eq!(key, key2, "both derive the same key");
        struct Shared(std::sync::Arc<MemRelay>);
        impl Relay for Shared {
            fn post(&self, m: &str, s: u64, b: &[u8]) -> Result<(), String> { self.0.post(m, s, b) }
            fn fetch(&self, m: &str, s: u64) -> Result<Option<Vec<u8>>, String> { self.0.fetch(m, s) }
        }
        let short = (Duration::from_millis(10), Duration::from_secs(3));
        let a = MailboxWire::new(vec![Box::new(Shared(relay.clone()))], a_send, a_recv, key)
            .with_polling(short.0, short.1);
        let b = MailboxWire::new(vec![Box::new(Shared(relay.clone()))], b_send, b_recv, key)
            .with_polling(short.0, short.1);
        (a, b, relay)
    }

    #[test]
    fn round_trips_multi_message_both_directions() {
        let (a, b, _r) = wires(&[7u8; 32]);
        a.send(b"hello from A".to_vec()).unwrap();
        assert_eq!(b.recv().unwrap(), b"hello from A");
        b.send(b"reply from B".to_vec()).unwrap();
        assert_eq!(a.recv().unwrap(), b"reply from B");
        // ordered second message on the same direction
        a.send(b"second".to_vec()).unwrap();
        assert_eq!(b.recv().unwrap(), b"second");
    }

    #[test]
    fn relay_cannot_read_or_tamper() {
        let (a, b, r) = wires(&[9u8; 32]);
        a.send(b"secret payload".to_vec()).unwrap();
        // The stored blob is ciphertext, not the plaintext.
        let stored: Vec<Vec<u8>> = r.store.lock().unwrap().values().cloned().collect();
        assert!(!stored.iter().any(|v| v.windows(6).any(|w| w == b"secret")), "relay sees only ciphertext");
        // Tamper one byte → recv fails authentication (not silent corruption).
        for v in r.store.lock().unwrap().values_mut() {
            v[0] ^= 0xFF;
        }
        assert_eq!(b.recv(), Err(WireError::BadContribution));
    }

    #[test]
    fn survives_a_censoring_relay_when_another_delivers() {
        // Two relays: one dead/censoring, one live. The wire must still work.
        let live = std::sync::Arc::new(MemRelay::default());
        let (a_send, a_recv, key) = derive(&[3u8; 32], true);
        let (b_send, b_recv, _k) = derive(&[3u8; 32], false);
        struct Shared(std::sync::Arc<MemRelay>);
        impl Relay for Shared {
            fn post(&self, m: &str, s: u64, b: &[u8]) -> Result<(), String> { self.0.post(m, s, b) }
            fn fetch(&self, m: &str, s: u64) -> Result<Option<Vec<u8>>, String> { self.0.fetch(m, s) }
        }
        let a = MailboxWire::new(
            vec![Box::new(DeadRelay), Box::new(Shared(live.clone()))],
            a_send, a_recv, key,
        ).with_polling(Duration::from_millis(10), Duration::from_secs(3));
        let b = MailboxWire::new(
            vec![Box::new(DeadRelay), Box::new(Shared(live.clone()))],
            b_send, b_recv, key,
        ).with_polling(Duration::from_millis(10), Duration::from_secs(3));
        a.send(b"through the live relay".to_vec()).unwrap();
        assert_eq!(b.recv().unwrap(), b"through the live relay");
    }

    #[test]
    fn recv_times_out_when_nothing_arrives() {
        let (a, _b, _r) = wires(&[1u8; 32]);
        // Nothing was sent on a's recv mailbox → times out as Closed, not hang.
        assert_eq!(a.recv(), Err(WireError::Closed));
    }

    /// End-to-end over the real `HttpRelay` against a minimal in-test HTTP
    /// store — proves the wire protocol works over actual HTTP, not just the
    /// in-memory double. The mock is a ~dumb keyed put/get, exactly what a
    /// production relay is.
    #[test]
    fn http_relay_round_trips_over_a_real_socket() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let store: Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Default::default());

        // Minimal HTTP store: POST /m/{mb}/{seq} stores the body; GET returns
        // it (404 if absent). Serves a fixed number of requests then exits.
        let srv_store = store.clone();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut s, _) = listener.accept().unwrap();
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).unwrap();
                let req = &buf[..n];
                let text = String::from_utf8_lossy(req);
                let mut lines = text.split("\r\n");
                let start = lines.next().unwrap_or("");
                let mut parts = start.split(' ');
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("").to_string();
                if method == "POST" {
                    // Body follows the blank line.
                    let body_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(n);
                    let body = req[body_start..n].to_vec();
                    srv_store.lock().unwrap().insert(path, body);
                    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
                } else {
                    match srv_store.lock().unwrap().get(&path) {
                        Some(b) => {
                            let hdr = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                                b.len()
                            );
                            s.write_all(hdr.as_bytes()).unwrap();
                            s.write_all(b).unwrap();
                        }
                        None => {
                            s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").unwrap();
                        }
                    }
                }
            }
        });

        let relay = HttpRelay::new(format!("http://{addr}"));
        relay.post("boxid", 0, b"ciphertext-here").unwrap();
        let got = relay.fetch("boxid", 0).unwrap();
        assert_eq!(got.as_deref(), Some(&b"ciphertext-here"[..]));
        server.join().unwrap();
    }
}
