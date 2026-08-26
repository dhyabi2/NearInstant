//! `dexd` — a minimal honest relay node (B4).
//!
//! Usage: `dexd <listen_addr> [--ws <ws_addr>] [--ws-origin <origin>] [--tor-proxy <addr>] [peer_addr ...]`
//!
//! Each node listens for peer connections, dials the peers given on the
//! command line, and floods every *verified* signed order to all connected
//! peers exactly once (de-duplicated by order hash). It holds the
//! deterministic consolidated book and never holds funds. Wire protocol:
//! length-prefixed frames, `0x01` = gossip one order (payload = order wire
//! bytes). This is the reference relay the browser client and makers gossip
//! through; a Tor/libp2p backend swaps the socket layer without touching the
//! relay logic.
//!
//! Hardening (audit #21): the relay is a public, unauthenticated service, so
//! it bounds its own exposure — a per-connection ingest budget, connection
//! caps for peers and browser sockets, a capped WebSocket message size, and a
//! periodic sweep of expired orders so the book/dedup sets never grow without
//! bound. Every accepted order is fanned out to BOTH the TCP peer mesh and the
//! WebSocket clients so browsers see live gossip, not just their own posts.
//!
//! Proof-of-funds: an order may carry a `NanoFundsProof` (order bytes followed
//! by proof bytes). With no Nano nodes configured (`--nano`), the relay can
//! only verify the *signature* (proof-of-key). Pass `--nano <url>` for two or
//! more independent nodes and the relay resolves the maker's live frontier
//! balance via a quorum and marks the order `pof_verified` only when that
//! balance actually covers the claim — turning proof-of-key into
//! proof-of-funds.

use dexd::relay;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tungstenite::protocol::WebSocketConfig;
use tungstenite::{accept_hdr_with_config, accept_with_config, Message};

use dex_core::order::{Side, SignedOrder};
use dex_core::pof::{MoneroReserveProof, NanoFundsProof};
use nano_ceremony::broadcast::{frontier_balance_quorum, NanoNode, RpcNode};
use relay::{Ingest, Relay};

const MSG_ORDER: u8 = 0x01;
/// Peer frame carrying an order immediately followed by its Nano
/// proof-of-funds (see `dex_core::pof::NanoFundsProof::to_wire`). Only the
/// peer mesh uses tagged frames; WebSocket clients send order bytes optionally
/// followed by the proof bytes (length-disambiguated).
const MSG_ORDER_WITH_POF: u8 = 0x02;
const ORDER_WIRE_LEN: usize = 193;
const MAX_MSG: u32 = 1 << 20;
/// Minimum independent Nano nodes required to certify a proof-of-funds.
const POF_QUORUM: usize = 2;

/// Write timeout on peer sockets (race F2): a peer that stops reading has its
/// blocking write fail after this instead of wedging the gossip thread.
const PEER_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on simultaneous TCP peers (audit #21: bound thread + fd use).
const MAX_PEERS: usize = 2_000;
/// Cap on simultaneous WebSocket browser clients.
const MAX_WS_CLIENTS: usize = 1_000;
/// How often an idle WS client polls its outbox (socket read timeout).
const WS_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Per-connection ingest budget: orders allowed within `INGEST_WINDOW`.
const INGEST_BUDGET: u32 = 200;
const INGEST_WINDOW: Duration = Duration::from_secs(1);
/// How often the sweeper prunes expired orders from the book + dedup set.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

type Peers = Arc<Mutex<HashMap<usize, TcpStream>>>;
/// Each connected browser holds an outbox of raw order frames to deliver;
/// `broadcast_ws` pushes every accepted order into every outbox.
type WsOutbox = Arc<Mutex<Vec<Vec<u8>>>>;
type WsPeers = Arc<Mutex<Vec<WsOutbox>>>;
/// Optional Nano nodes used to resolve live balances for proof-of-funds.
type NanoNodes = Arc<Vec<RpcNode>>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A proof attached to an order, tagged by the asset the order sells.
enum AttachedProof {
    Nano(NanoFundsProof),
    Xmr(MoneroReserveProof),
}

/// Split a WebSocket payload into an order and (optionally) its proof. A bare
/// order is 193 bytes; `order || proof` is longer. The proof type follows the
/// order's `side` — a sell-XNO order carries a [`NanoFundsProof`], a sell-XMR
/// order a [`MoneroReserveProof`] — so the two assets never cross-contaminate.
fn split_order_proof(payload: &[u8]) -> (Option<SignedOrder>, Option<AttachedProof>) {
    if payload.len() < ORDER_WIRE_LEN {
        return (None, None);
    }
    let order = SignedOrder::from_wire(&payload[..ORDER_WIRE_LEN]);
    let tail = payload.get(ORDER_WIRE_LEN..).unwrap_or(&[]);
    let proof = match order.as_ref().map(|o| o.body.side) {
        Some(Side::SellXno) => NanoFundsProof::from_wire(tail).map(AttachedProof::Nano),
        Some(Side::SellXmr) => MoneroReserveProof::from_wire(tail).map(AttachedProof::Xmr),
        None => None,
    };
    (order, proof)
}

/// Decide whether an order is *proof-of-funds* verified.
///
/// - **Sell-XNO** (`NanoFundsProof`): with no Nano nodes the relay can only
///   attest the signature (proof-of-key); with nodes it resolves the maker's
///   live frontier balance across a quorum and marks verified only when that
///   balance actually covers the claim (`FundsStatus::Funded`).
/// - **Sell-XMR** (`MoneroReserveProof`): the relay can only do the offline
///   structural/binding check (`matches_order`); the authoritative solvency
///   check is `check_reserve_proof` against a wallet, done by the taker at
///   take time, never by the relay.
fn pof_verified(proof: &AttachedProof, order: &SignedOrder, now: u64, nodes: &NanoNodes) -> bool {
    match proof {
        AttachedProof::Nano(p) => {
            // The proof must bind to exactly this order (maker, nonce, pof_hash).
            if !p.matches_order(order) {
                return false;
            }
            if nodes.is_empty() {
                // No balance oracle: signature + expiry only.
                return p.verify(now);
            }
            let refs: Vec<&dyn NanoNode> = nodes.iter().map(|n| n as &dyn NanoNode).collect();
            match frontier_balance_quorum(&refs, &p.account, POF_QUORUM) {
                Some(balance) => p.assess(now, Some(balance)).is_funded(),
                // Couldn't reach a quorum → never claim verified.
                None => false,
            }
        }
        AttachedProof::Xmr(p) => p.matches_order(order),
    }
}

/// A simple per-connection token bucket (orders per second).
struct RateLimit {
    window_start: Instant,
    count: u32,
}

impl RateLimit {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            count: 0,
        }
    }

    /// True if one more order may be ingested this window.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= INGEST_WINDOW {
            self.window_start = now;
            self.count = 0;
        }
        if self.count >= INGEST_BUDGET {
            return false;
        }
        self.count += 1;
        true
    }
}

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

fn write_frame(stream: &mut TcpStream, tag: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(tag);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)
}

/// Minimal SOCKS5 CONNECT (no-auth) — the same logic as `transport::socks`,
/// inlined so the relay need not depend on the heavy swap crates. Used to dial
/// peers (including `.onion`) through a local Tor proxy.
fn socks5_connect(proxy: &str, host: &str, port: u16) -> std::io::Result<TcpStream> {
    if host.len() > 255 {
        return Err(std::io::Error::other("host too long"));
    }
    let mut stream = TcpStream::connect(proxy)?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut sel = [0u8; 2];
    stream.read_exact(&mut sel)?;
    if sel != [0x05, 0x00] {
        return Err(std::io::Error::other("socks5 handshake failed"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(std::io::Error::other("socks5 connect refused"));
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l)?;
            l[0] as usize
        }
        _ => return Err(std::io::Error::other("bad socks5 addr type")),
    };
    let mut skip = vec![0u8; addr_len + 2];
    stream.read_exact(&mut skip)?;
    Ok(stream)
}

/// Dial a peer `host:port`. When `tor_proxy` is set, route the connection
/// through the SOCKS5 proxy (Tor) so `.onion` peers and privacy-preserving
/// clearnet dials both work.
fn dial_peer(peer: &str, tor_proxy: Option<&str>) -> std::io::Result<TcpStream> {
    if let Some(proxy) = tor_proxy {
        let (host, port) = peer
            .rsplit_once(':')
            .ok_or_else(|| std::io::Error::other("bad peer addr"))?;
        let port: u16 = port
            .parse()
            .map_err(|_| std::io::Error::other("bad peer port"))?;
        socks5_connect(proxy, host, port)
    } else {
        TcpStream::connect(peer)
    }
}

/// Flood a payload to every connected peer except `from`.
///
/// Race F2 (head-of-line blocking): the previous version held the `peers` lock
/// across every blocking `write_all`, so one peer whose TCP send buffer was
/// full (a slow or malicious consumer that never reads) stalled the guard
/// indefinitely — blocking all other gossip, new-connection inserts, and
/// dead-peer cleanup, i.e. a whole-relay DoS from a single stuck socket.
///
/// Now we snapshot the target stream handles under the lock (fast, `try_clone`),
/// release it, then do the blocking writes on the clones. A stalled peer no
/// longer holds the shared lock; combined with the write timeout set on each
/// accepted/dialed stream, it fails and is reaped instead of wedging the relay.
fn flood(peers: &Peers, from: Option<usize>, payload: &[u8]) {
    let targets: Vec<(usize, TcpStream)> = {
        let map = peers.lock().unwrap();
        map.iter()
            .filter(|(&id, _)| Some(id) != from)
            .filter_map(|(&id, s)| s.try_clone().ok().map(|c| (id, c)))
            .collect()
    };
    let mut dead = Vec::new();
    for (id, mut stream) in targets {
        if write_frame(&mut stream, MSG_ORDER, payload).is_err() {
            dead.push(id);
        }
    }
    if !dead.is_empty() {
        let mut map = peers.lock().unwrap();
        for id in dead {
            map.remove(&id);
        }
    }
}

/// Push an accepted order's wire bytes into every browser outbox (audit #21:
/// browsers must see live gossip from peers and other browsers, not only the
/// initial snapshot and their own posts).
fn broadcast_ws(ws_peers: &WsPeers, payload: &[u8]) {
    let outboxes: Vec<WsOutbox> = ws_peers.lock().unwrap().clone();
    for ob in outboxes {
        ob.lock().unwrap().push(payload.to_vec());
    }
}

/// Handle one peer connection: ingest gossip, re-flood the new-and-valid.
fn serve_peer(
    id: usize,
    mut stream: TcpStream,
    relay: Arc<Relay>,
    peers: Peers,
    ws_peers: WsPeers,
    nodes: NanoNodes,
) {
    // Send the current book to a joining peer so it can anchor without waiting
    // for fresh gossip (mirrors the WebSocket connect snapshot).
    for wire in relay.snapshot() {
        if write_frame(&mut stream, MSG_ORDER, &wire).is_err() {
            break;
        }
    }
    let mut rl = RateLimit::new();
    loop {
        match read_frame(&mut stream) {
            Ok((MSG_ORDER, payload)) => {
                if !rl.allow() {
                    // Audit #21: a peer flooding faster than the budget is dropped.
                    break;
                }
                if let Some(order) = SignedOrder::from_wire(&payload) {
                    match relay.ingest(order, now(), false) {
                        Ingest::Accepted => {
                            flood(&peers, Some(id), &payload);
                            broadcast_ws(&ws_peers, &payload);
                        }
                        Ingest::Duplicate | Ingest::Rejected => {}
                    }
                }
            }
            Ok((MSG_ORDER_WITH_POF, payload)) => {
                if !rl.allow() {
                    break;
                }
                // Order (fixed 193 bytes) followed by the proof bytes.
                let split = split_order_proof(&payload);
                if let Some(order) = split.0 {
                    let verified = split.1
                        .as_ref()
                        .map(|p| pof_verified(p, &order, now(), &nodes))
                        .unwrap_or(false);
                    if relay.ingest(order, now(), verified) == Ingest::Accepted {
                        flood(&peers, Some(id), &payload[..ORDER_WIRE_LEN]);
                        broadcast_ws(&ws_peers, &payload[..ORDER_WIRE_LEN]);
                    }
                }
            }
            Ok(_) => {} // unknown tag: ignore
            Err(_) => break,
        }
    }
    peers.lock().unwrap().remove(&id);
}

/// Serve browser clients over WebSocket, bridging binary frames to the same
/// relay book and peer flood. nginx terminates TLS and proxies to this.
fn serve_ws(
    addr: String,
    relay: Arc<Relay>,
    peers: Peers,
    ws_peers: WsPeers,
    next_id: Arc<Mutex<usize>>,
    ws_origin: Option<String>,
    nodes: NanoNodes,
) {
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ws bind {addr} failed: {e}");
            return;
        }
    };
    eprintln!("dexd ws gateway on {addr}");
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if ws_peers.lock().unwrap().len() >= MAX_WS_CLIENTS {
            drop(stream);
            continue;
        }
        let (relay, peers, ws_peers, next_id, origin, nodes) = (
            relay.clone(),
            peers.clone(),
            ws_peers.clone(),
            next_id.clone(),
            ws_origin.clone(),
            nodes.clone(),
        );
        thread::spawn(move || ws_client(stream, relay, peers, ws_peers, next_id, origin, nodes));
    }
}

fn ws_client(
    stream: TcpStream,
    relay: Arc<Relay>,
    peers: Peers,
    ws_peers: WsPeers,
    _next_id: Arc<Mutex<usize>>,
    ws_origin: Option<String>,
    nodes: NanoNodes,
) {
    // Audit #21: cap the WS message/frame size so a client cannot make us
    // buffer an unbounded payload (an order frame is only ~193 bytes).
    let config = Some(WebSocketConfig {
        max_message_size: Some(MAX_MSG as usize),
        max_frame_size: Some(MAX_MSG as usize),
        ..Default::default()
    });
    let mut ws = match ws_origin {
        // Origin pinning (audit #21): when `--ws-origin` is set, reject any
        // handshake whose Origin header doesn't match — a foreign site cannot
        // open a socket to the relay in a victim's browser.
        Some(origin) => {
            // `ErrorResponse` is fixed by tungstenite's `Callback` trait to a
            // full `http::Response`; its size is imposed by the API.
            #[allow(clippy::result_large_err)]
            let cb = move |req: &tungstenite::handshake::server::Request,
                           resp: tungstenite::handshake::server::Response| {
                let ok = req
                    .headers()
                    .get("Origin")
                    .and_then(|o| o.to_str().ok())
                    .map(|o| o == origin.as_str())
                    .unwrap_or(false);
                if ok {
                    Ok(resp)
                } else {
                    Err(http::Response::builder()
                        .status(403)
                        .body(Some("forbidden origin".to_string()))
                        .unwrap())
                }
            };
            match accept_hdr_with_config(stream, cb, config) {
                Ok(w) => w,
                Err(_) => return,
            }
        }
        None => match accept_with_config(stream, config) {
            Ok(w) => w,
            Err(_) => return,
        },
    };
    // Poll the outbox while idle: a short read timeout surfaces
    // `WouldBlock`/`TimedOut`, which we treat as "flush pending broadcasts".
    let _ = ws.get_ref().set_read_timeout(Some(WS_POLL_INTERVAL));

    let outbox: WsOutbox = Arc::new(Mutex::new(Vec::new()));
    ws_peers.lock().unwrap().push(outbox.clone());

    // On connect, replay the current book so the browser starts populated.
    for wire in relay.snapshot() {
        if ws.send(Message::Binary(wire)).is_err() {
            ws_peers.lock().unwrap().retain(|o| !Arc::ptr_eq(o, &outbox));
            return;
        }
    }

    let mut rl = RateLimit::new();
    loop {
        // Deliver any orders broadcast since the last read.
        let pending: Vec<Vec<u8>> = std::mem::take(&mut *outbox.lock().unwrap());
        for p in pending {
            if ws.send(Message::Binary(p)).is_err() {
                ws_peers.lock().unwrap().retain(|o| !Arc::ptr_eq(o, &outbox));
                return;
            }
        }
        match ws.read() {
            Ok(Message::Binary(payload)) => {
                if !rl.allow() {
                    break;
                }
                // A WS frame is either a bare order, or order followed by its
                // proof (length-disambiguated). Re-flood only the order bytes.
                let (order, proof) = split_order_proof(&payload);
                if let Some(order) = order {
                    let verified = proof
                        .as_ref()
                        .map(|p| pof_verified(p, &order, now(), &nodes))
                        .unwrap_or(false);
                    if relay.ingest(order, now(), verified) == Ingest::Accepted {
                        flood(&peers, None, &payload[..ORDER_WIRE_LEN]);
                        // Includes this client's own outbox → its own order is
                        // echoed back so the UI can confirm ingest.
                        broadcast_ws(&ws_peers, &payload[..ORDER_WIRE_LEN]);
                    }
                }
            }
            Ok(Message::Ping(p)) => {
                let _ = ws.send(Message::Pong(p));
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(tungstenite::Error::Io(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
    ws_peers.lock().unwrap().retain(|o| !Arc::ptr_eq(o, &outbox));
}

/// Periodically drop expired orders from the book and the dedup set (audit
/// #21: without this, expired orders and their hashes accumulate until the
/// book cap refuses every new order).
fn start_sweeper(relay: Arc<Relay>) {
    thread::spawn(move || loop {
        thread::sleep(SWEEP_INTERVAL);
        let n = relay.sweep(now());
        if n > 0 {
            eprintln!("dexd: swept {n} expired orders");
        }
    });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: dexd <listen_addr> [--ws <ws_addr>] [--ws-origin <origin>] [--tor-proxy <addr>] [--nano <url> ...] [peer_addr ...]");
        std::process::exit(2);
    }
    let listen = &args[1];
    let relay = Arc::new(Relay::new());
    let peers: Peers = Arc::new(Mutex::new(HashMap::new()));
    let ws_peers: WsPeers = Arc::new(Mutex::new(Vec::new()));
    let next_id = Arc::new(Mutex::new(0usize));

    start_sweeper(relay.clone());

    // Parse `--ws <addr>`, `--ws-origin <origin>`, `--tor-proxy <addr>`,
    // `--nano <url>` first so the peer list that follows is unambiguous.
    let mut ws_addr: Option<String> = None;
    let mut ws_origin: Option<String> = None;
    let mut tor_proxy: Option<String> = None;
    let mut nano_urls: Vec<String> = Vec::new();
    let mut peers_args: Vec<String> = Vec::new();
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--ws" if i + 1 < args.len() => {
                ws_addr = Some(args[i + 1].clone());
                i += 2;
            }
            "--ws-origin" if i + 1 < args.len() => {
                ws_origin = Some(args[i + 1].clone());
                i += 2;
            }
            "--tor-proxy" if i + 1 < args.len() => {
                tor_proxy = Some(args[i + 1].clone());
                i += 2;
            }
            "--nano" if i + 1 < args.len() => {
                nano_urls.push(args[i + 1].clone());
                i += 2;
            }
            _ => {
                peers_args.push(args[i].clone());
                i += 1;
            }
        }
    }

    // Nano nodes for proof-of-funds balance resolution (optional). Use an API
    // key only when one is set (never an empty key).
    let nano_key = std::env::var("NANO_RPC_KEY").unwrap_or_default();
    let nano_nodes: NanoNodes = Arc::new(
        nano_urls
            .iter()
            .map(|u| {
                if nano_key.is_empty() {
                    RpcNode::new(u)
                } else {
                    RpcNode::with_key(u, &nano_key)
                }
            })
            .collect(),
    );
    if !nano_nodes.is_empty() {
        eprintln!(
            "dexd: proof-of-funds balance checks on ({} nano node(s))",
            nano_nodes.len()
        );
    } else {
        eprintln!("dexd: no --nano nodes — PoF is signature-only (proof-of-key)");
    }

    // Dial configured peers (optionally over Tor).
    for peer in &peers_args {
        if peers.lock().unwrap().len() >= MAX_PEERS {
            eprintln!("warn: peer cap reached, not dialing {peer}");
            continue;
        }
        match dial_peer(peer, tor_proxy.as_deref()) {
            Ok(stream) => {
                let _ = stream.set_write_timeout(Some(PEER_WRITE_TIMEOUT));
                let id = {
                    let mut n = next_id.lock().unwrap();
                    let id = *n;
                    *n += 1;
                    id
                };
                peers.lock().unwrap().insert(id, stream.try_clone().unwrap());
                let (r, p, w, nd) = (
                    relay.clone(),
                    peers.clone(),
                    ws_peers.clone(),
                    nano_nodes.clone(),
                );
                thread::spawn(move || serve_peer(id, stream, r, p, w, nd));
            }
            Err(e) => eprintln!("warn: could not connect to peer {peer}: {e}"),
        }
    }

    if let Some(wa) = ws_addr {
        let (r, p, w, n, nd) = (
            relay.clone(),
            peers.clone(),
            ws_peers.clone(),
            next_id.clone(),
            nano_nodes.clone(),
        );
        let origin = ws_origin.clone();
        thread::spawn(move || serve_ws(wa, r, p, w, n, origin, nd));
    }

    let listener = TcpListener::bind(listen).expect("bind");
    eprintln!(
        "dexd listening on {listen} ({} peers)",
        peers.lock().unwrap().len()
    );
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if peers.lock().unwrap().len() >= MAX_PEERS {
            drop(stream);
            continue;
        }
        let _ = stream.set_write_timeout(Some(PEER_WRITE_TIMEOUT));
        let id = {
            let mut n = next_id.lock().unwrap();
            let id = *n;
            *n += 1;
            id
        };
        peers.lock().unwrap().insert(id, stream.try_clone().unwrap());
        let (r, p, w, nd) = (
            relay.clone(),
            peers.clone(),
            ws_peers.clone(),
            nano_nodes.clone(),
        );
        thread::spawn(move || serve_peer(id, stream, r, p, w, nd));
    }
}
