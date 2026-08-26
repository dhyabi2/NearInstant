//! SOCKS5 handshake test against a local mock proxy: proves connect_via
//! speaks the protocol correctly (greeting, no-auth, domain CONNECT, reply
//! parsing) without needing a real Tor daemon. When a real Tor proxy is
//! present at 127.0.0.1:9050, the ignored `live_tor` test dials a .onion.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use transport::socks::{connect_via, SocksError};

/// A minimal SOCKS5 proxy that accepts no-auth CONNECT, replies success,
/// then bridges the client to a fixed backend it connects to itself. For the
/// test it just echoes a marker so we can confirm the tunnel is usable.
fn mock_socks(marker: &'static [u8]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let (mut c, _) = listener.accept().unwrap();
        // Greeting.
        let mut g = [0u8; 3];
        c.read_exact(&mut g).unwrap();
        assert_eq!(g, [0x05, 0x01, 0x00], "no-auth greeting");
        c.write_all(&[0x05, 0x00]).unwrap();
        // CONNECT request.
        let mut head = [0u8; 5];
        c.read_exact(&mut head).unwrap();
        assert_eq!(&head[..4], &[0x05, 0x01, 0x00, 0x03], "domain CONNECT");
        let host_len = head[4] as usize;
        let mut rest = vec![0u8; host_len + 2];
        c.read_exact(&mut rest).unwrap();
        // Success reply with a dummy IPv4 bound address.
        c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).unwrap();
        // Now the tunnel is "open" — send the marker so the client can read it.
        c.write_all(marker).unwrap();
    });
    addr
}

#[test]
fn socks5_handshake_and_tunnel() {
    let proxy = mock_socks(b"TUNNEL-OK");
    let mut stream: TcpStream =
        connect_via(&proxy, "example.onion", 8080).expect("socks connect");
    let mut buf = [0u8; 9];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"TUNNEL-OK", "bytes flow through the negotiated tunnel");
}

#[test]
fn rejects_overlong_host() {
    let long = "a".repeat(256);
    assert!(matches!(
        connect_via("127.0.0.1:1", &long, 80),
        Err(SocksError::HostTooLong)
    ));
}

#[test]
#[ignore = "requires a running Tor proxy at 127.0.0.1:9050"]
fn live_tor_reaches_an_onion() {
    // Dial a well-known .onion over the local Tor proxy; success is simply
    // completing the SOCKS negotiation and TCP connect to the hidden service.
    use transport::socks::connect_tor;
    let r = connect_tor("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", 80);
    assert!(r.is_ok(), "Tor circuit to .onion established: {r:?}");
}
