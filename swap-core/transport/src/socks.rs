//! SOCKS5 client for Tor: dial a destination through a local Tor proxy
//! (default `127.0.0.1:9050`), returning a connected `TcpStream` that
//! [`crate::tcp::TcpWire`] wraps unchanged. This is the whole Tor
//! integration — the ceremonies and relay above the `Wire` trait never learn
//! whether their bytes ride clearnet TCP or a Tor circuit to a `.onion`.
//!
//! No-auth CONNECT only (Tor's SOCKS port needs no authentication). Domain
//! names — including `.onion` — are sent as SOCKS5 domain addresses so the
//! proxy resolves them, never the local resolver (no DNS leak).

use std::io::{Read, Write};
use std::net::TcpStream;

/// The default Tor SOCKS5 address.
pub const DEFAULT_TOR_PROXY: &str = "127.0.0.1:9050";

/// SOCKS5 errors.
#[derive(Debug)]
pub enum SocksError {
    Io(std::io::Error),
    /// The proxy refused the version/method handshake.
    Handshake,
    /// The proxy returned a non-success reply code.
    Reply(u8),
    /// Destination host too long for a SOCKS5 domain address (>255 bytes).
    HostTooLong,
}

impl From<std::io::Error> for SocksError {
    fn from(e: std::io::Error) -> Self {
        SocksError::Io(e)
    }
}

/// Connect to `dest_host:dest_port` through the SOCKS5 proxy at `proxy_addr`.
/// `dest_host` may be a hostname (resolved by the proxy), an IPv4 literal, or
/// a `.onion` address.
pub fn connect_via(
    proxy_addr: &str,
    dest_host: &str,
    dest_port: u16,
) -> Result<TcpStream, SocksError> {
    if dest_host.len() > 255 {
        return Err(SocksError::HostTooLong);
    }
    let mut stream = TcpStream::connect(proxy_addr)?;

    // Greeting: VER=5, one method, 0x00 = no auth.
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut sel = [0u8; 2];
    stream.read_exact(&mut sel)?;
    if sel[0] != 0x05 || sel[1] != 0x00 {
        return Err(SocksError::Handshake);
    }

    // CONNECT request with a domain address (ATYP=0x03).
    let mut req = vec![0x05, 0x01, 0x00, 0x03, dest_host.len() as u8];
    req.extend_from_slice(dest_host.as_bytes());
    req.extend_from_slice(&dest_port.to_be_bytes());
    stream.write_all(&req)?;

    // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(SocksError::Reply(head[1]));
    }
    // Drain the bound address per its type.
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l)?;
            l[0] as usize
        }
        _ => return Err(SocksError::Handshake),
    };
    let mut skip = vec![0u8; addr_len + 2]; // address + port
    stream.read_exact(&mut skip)?;

    Ok(stream)
}

/// Connect through the default Tor proxy.
pub fn connect_tor(dest_host: &str, dest_port: u16) -> Result<TcpStream, SocksError> {
    connect_via(DEFAULT_TOR_PROXY, dest_host, dest_port)
}
