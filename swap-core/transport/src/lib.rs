//! Block 9a: the two-party ceremony transport.
//!
//! Every earlier battery drove ceremonies in-process (one function holding
//! both parties' maps). This crate splits them across a byte-oriented wire:
//! each party runs its own driver, exchanging framed messages — the exact
//! shape a libp2p/Tor stream (or any socket) will carry. The [`Wire`] trait
//! is the only integration point for real transports; [`loopback`] provides
//! an in-memory pair for tests and same-host use.
//!
//! Framing is deliberately minimal: one type byte + u32 length + payload.
//! Everything inside payloads is already produced/consumed as bytes by the
//! underlying crates (frost serializations, Cosigner blobs, block encodings).

#![forbid(unsafe_code)]

use std::sync::mpsc::{channel, Receiver, Sender};

pub mod ceremonies;
pub mod mailbox;
pub mod socks;
pub mod tcp;
pub mod ws;

/// A byte-message channel to the counterparty.
pub trait Wire {
    fn send(&self, msg: Vec<u8>) -> Result<(), WireError>;
    fn recv(&self) -> Result<Vec<u8>, WireError>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    Closed,
    /// A frame arrived with an unexpected type tag.
    UnexpectedMessage { expected: u8, got: u8 },
    /// Payload failed to parse.
    Malformed,
    /// The counterparty's contribution failed cryptographic checks.
    BadContribution,
}

/// In-memory wire pair (two connected endpoints).
pub struct Loopback {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

/// Create a connected pair.
pub fn loopback() -> (Loopback, Loopback) {
    let (tx_a, rx_b) = channel();
    let (tx_b, rx_a) = channel();
    (
        Loopback { tx: tx_a, rx: rx_a },
        Loopback { tx: tx_b, rx: rx_b },
    )
}

impl Wire for Loopback {
    fn send(&self, msg: Vec<u8>) -> Result<(), WireError> {
        self.tx.send(msg).map_err(|_| WireError::Closed)
    }
    fn recv(&self) -> Result<Vec<u8>, WireError> {
        self.rx.recv().map_err(|_| WireError::Closed)
    }
}

/// Frame tags.
pub mod tag {
    pub const COMMITMENTS: u8 = 1;
    pub const SIG_SHARE: u8 = 2;
    pub const CLSAG_PREPROCESS: u8 = 3;
    pub const CLSAG_SHARE: u8 = 4;
    pub const DKG_ROUND1: u8 = 5;
    pub const DKG_ROUND2: u8 = 6;
    pub const XMR_CONTRIB: u8 = 8;
    pub const BOB_DEST: u8 = 9;
    /// Alice → Bob: the pending-send hash funding the joint Nano account.
    /// Sent AFTER the joint account is known (the account only exists once
    /// the DKG finishes, so funding — and this hash — happen mid-session).
    pub const OPEN_LINK: u8 = 10;
    /// Bob → Alice: the Monero block height of the matured XMR lock, so Alice's
    /// sweep scans a tight window instead of hundreds of blocks (8 bytes LE).
    pub const LOCK_HEIGHT: u8 = 11;
}

/// Send one framed message.
pub fn send_frame(wire: &impl Wire, t: u8, payload: &[u8]) -> Result<(), WireError> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(t);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    wire.send(frame)
}

/// Receive one framed message, requiring type `t`.
pub fn recv_frame(wire: &impl Wire, t: u8) -> Result<Vec<u8>, WireError> {
    let frame = wire.recv()?;
    if frame.len() < 5 {
        return Err(WireError::Malformed);
    }
    if frame[0] != t {
        return Err(WireError::UnexpectedMessage {
            expected: t,
            got: frame[0],
        });
    }
    let len = u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize;
    if frame.len() != 5 + len {
        return Err(WireError::Malformed);
    }
    Ok(frame[5..].to_vec())
}
