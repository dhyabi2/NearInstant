//! Real-socket transport: length-prefixed messages over TCP. The same
//! [`crate::Wire`] the ceremonies already run on — pointing it at a Tor
//! SOCKS5 stream later changes nothing above this layer.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Mutex;

use crate::{Wire, WireError};

/// Message cap (1 MiB) — ceremony messages are tiny; anything huge is abuse.
const MAX_MSG: u32 = 1 << 20;

/// A connected TCP endpoint speaking length-prefixed messages.
pub struct TcpWire {
    reader: Mutex<TcpStream>,
    writer: Mutex<TcpStream>,
}

impl TcpWire {
    pub fn new(stream: TcpStream) -> std::io::Result<Self> {
        let reader = stream.try_clone()?;
        Ok(Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(stream),
        })
    }

    /// Connect to a listening counterparty.
    pub fn connect(addr: impl ToSocketAddrs) -> std::io::Result<Self> {
        Self::new(TcpStream::connect(addr)?)
    }

    /// Accept one counterparty on `listener`.
    pub fn accept(listener: &TcpListener) -> std::io::Result<Self> {
        let (stream, _) = listener.accept()?;
        Self::new(stream)
    }
}

impl Wire for TcpWire {
    fn send(&self, msg: Vec<u8>) -> Result<(), WireError> {
        if msg.len() as u32 > MAX_MSG {
            return Err(WireError::Malformed);
        }
        let mut w = self.writer.lock().map_err(|_| WireError::Closed)?;
        w.write_all(&(msg.len() as u32).to_be_bytes())
            .and_then(|_| w.write_all(&msg))
            .map_err(|_| WireError::Closed)
    }

    fn recv(&self) -> Result<Vec<u8>, WireError> {
        let mut r = self.reader.lock().map_err(|_| WireError::Closed)?;
        let mut len_bytes = [0u8; 4];
        r.read_exact(&mut len_bytes).map_err(|_| WireError::Closed)?;
        let len = u32::from_be_bytes(len_bytes);
        if len > MAX_MSG {
            return Err(WireError::Malformed);
        }
        let mut buf = vec![0u8; len as usize];
        r.read_exact(&mut buf).map_err(|_| WireError::Closed)?;
        Ok(buf)
    }
}
