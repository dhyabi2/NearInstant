//! Browser-compatible transport: the [`crate::Wire`] ceremonies run on, over
//! a WebSocket.
//!
//! Raw TCP is impossible inside a browser, and [`crate::tcp::TcpWire`] does
//! not fit a web client. A WebSocket is the full-duplex binary channel a
//! browser already has natively (and the one the relay `dexd` already
//! terminates for the web UI). This module closes that gap: the identical
//! DKG / FROST / adaptor ceremony runs over a WebSocket exactly as it does
//! over TCP or loopback — same framing, same [`crate::Wire`] trait.
//!
//! TLS is deliberately NOT handled here: the deployment model terminates TLS
//! at a reverse proxy (nginx → `dexd` WS gateway), so the [`WsWire`] always
//! sees a plain `ws://` connection to localhost or a TLS-terminating proxy.
//! The ceremony payloads themselves are public commitments and encrypted
//! shares, so a WebSocket relay in the middle learns nothing secret (the
//! relay is untrusted by construction).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;

use tungstenite::handshake::server::{Request, Response};
use tungstenite::{accept, accept_hdr, connect, Message, WebSocket};

use crate::{Wire, WireError};

/// A connected WebSocket endpoint speaking the ceremony framing. `S` is the
/// underlying stream (plain `TcpStream` on the server side, `MaybeTlsStream`
/// on the client side).
pub struct WsWire<S> {
    ws: Mutex<WebSocket<S>>,
}

impl<S> WsWire<S> {
    fn from_socket(ws: WebSocket<S>) -> Self {
        Self { ws: Mutex::new(ws) }
    }
}

impl WsWire<tungstenite::stream::MaybeTlsStream<TcpStream>> {
    /// Connect to a `ws://` counterparty (plain; TLS terminates at a proxy).
    pub fn connect(url: &str) -> Result<Self, tungstenite::Error> {
        let (ws, _response) = connect(url)?;
        Ok(Self::from_socket(ws))
    }
}

impl WsWire<TcpStream> {
    /// Accept a counterparty on a raw TCP stream (server side).
    pub fn accept(stream: TcpStream) -> Result<Self, String> {
        let ws = accept(stream).map_err(|e| e.to_string())?;
        Ok(Self::from_socket(ws))
    }

    /// Accept and enforce a browser `Origin` allowlist — the localhost-helper
    /// CSRF defense. A malicious page in the user's browser can open a socket
    /// to `127.0.0.1`; the browser always sends an `Origin` header, so a
    /// disallowed origin is refused outright. A connection with NO `Origin`
    /// (a non-browser client) is admitted here and must still pass the
    /// caller's own token gate.
    pub fn accept_with_origin(stream: TcpStream, allow_origins: &[String]) -> Result<Self, String> {
        let allow = allow_origins.to_vec();
        #[allow(clippy::result_large_err)]
        let cb = move |req: &Request, resp: Response| {
            let origin = req.headers().get("Origin").and_then(|o| o.to_str().ok());
            let ok = match origin {
                None => true,
                Some(o) => allow.iter().any(|a| a == o),
            };
            if ok {
                Ok(resp)
            } else {
                Err(http::Response::builder()
                    .status(403)
                    .body(Some("forbidden origin".to_string()))
                    .unwrap())
            }
        };
        let ws = accept_hdr(stream, cb).map_err(|e| e.to_string())?;
        Ok(Self::from_socket(ws))
    }
}

impl<S: Read + Write> Wire for WsWire<S> {
    fn send(&self, msg: Vec<u8>) -> Result<(), WireError> {
        let mut ws = self.ws.lock().map_err(|_| WireError::Closed)?;
        ws.send(Message::Binary(msg)).map_err(|_| WireError::Closed)
    }

    fn recv(&self) -> Result<Vec<u8>, WireError> {
        let mut ws = self.ws.lock().map_err(|_| WireError::Closed)?;
        loop {
            match ws.read().map_err(|_| WireError::Closed)? {
                Message::Binary(bytes) => return Ok(bytes),
                // Be liberal: a peer sending UTF-8 framing still carries bytes.
                Message::Text(text) => return Ok(text.into_bytes()),
                Message::Ping(payload) => {
                    let _ = ws.send(Message::Pong(payload));
                }
                Message::Pong(_) => {}
                Message::Close(_) => return Err(WireError::Closed),
                Message::Frame(_) => {}
            }
        }
    }
}
