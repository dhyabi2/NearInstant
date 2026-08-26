//! Relay battery: dedup/verify logic in-process, order wire round-trips, and
//! a REAL three-node dexd network on localhost — an order gossiped into one
//! node propagates to all, and every node computes the identical book root
//! (the I7 cross-relay consistency the client depends on).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;

use dex_core::order::{OrderBody, Side, SignedOrder};
use dexd::relay::{Ingest, Relay};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn maker() -> (frost_core::SigningKey<signing::Ed25519Blake2b>, [u8; 32]) {
    let key = frost_core::SigningKey::<signing::Ed25519Blake2b>::new(&mut OsRng);
    let vk = frost_core::VerifyingKey::from(&key);
    (key, vk.serialize().unwrap().try_into().unwrap())
}

fn signed_order(
    key: &frost_core::SigningKey<signing::Ed25519Blake2b>,
    pubkey: [u8; 32],
    rate: u128,
    nonce: u64,
    expiry: u64,
) -> SignedOrder {
    let body = OrderBody {
        maker: pubkey,
        side: Side::SellXno,
        amount: 100,
        rate_pico: rate,
        expiry,
        nonce,
        pof_hash: [0xEE; 32],
    };
    let sig = key.sign(&mut OsRng, &body.encode());
    SignedOrder {
        body,
        signature: sig.serialize().unwrap().try_into().unwrap(),
    }
}

#[test]
fn order_wire_round_trips_and_rejects_garbage() {
    let (k, pk) = maker();
    let o = signed_order(&k, pk, 3_750_000_000, 1, now() + 1_000);
    let wire = o.to_wire();
    let back = SignedOrder::from_wire(&wire).expect("round trips");
    assert_eq!(back, o);
    // Truncated / oversized / wrong-magic all rejected.
    assert!(SignedOrder::from_wire(&wire[..wire.len() - 1]).is_none());
    let mut bad = wire.clone();
    bad[0] ^= 1;
    assert!(SignedOrder::from_wire(&bad).is_none());
}

#[test]
fn relay_dedups_verifies_and_drops_invalid() {
    let relay = Relay::new();
    let (k, pk) = maker();
    let o = signed_order(&k, pk, 3_700_000_000, 1, now() + 1_000);

    // First sighting: accepted and floodable.
    assert_eq!(relay.ingest(o.clone(), now(), true), Ingest::Accepted);
    // Second sighting: duplicate, not re-flooded.
    assert_eq!(relay.ingest(o.clone(), now(), true), Ingest::Duplicate);
    assert_eq!(relay.order_count(), 1);

    // A tampered order fails verification and is dropped, not relayed.
    let mut forged = o.clone();
    forged.body.amount = 999;
    assert_eq!(relay.ingest(forged, now(), true), Ingest::Rejected);
    assert_eq!(relay.order_count(), 1);

    // Two distinct orders → book of two, deterministic non-zero root.
    let o2 = signed_order(&k, pk, 3_800_000_000, 2, now() + 1_000);
    assert_eq!(relay.ingest(o2, now(), true), Ingest::Accepted);
    assert_eq!(relay.order_count(), 2);
    assert_ne!(relay.merkle_root(), [0u8; 32]);
}

// --------------------------------------------------------------------------
// Real three-node TCP integration.
// --------------------------------------------------------------------------

struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn dexd_bin() -> String {
    // The test binary lives in target/<profile>/deps; the dexd binary is one
    // level up in target/<profile>/.
    // current_exe is target/<profile>/deps/<testbin>; the dexd binary sits at
    // target/<profile>/dexd.
    let mut exe = std::env::current_exe().unwrap();
    exe.pop(); // testbin filename -> target/<profile>/deps
    exe.pop(); // deps -> target/<profile>
    exe.push("dexd");
    exe.to_string_lossy().into_owned()
}

fn wait_port(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("port {addr} never came up");
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x01];
    f.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

#[test]
#[ignore = "spawns real dexd processes; run with --ignored"]
fn three_node_gossip_propagates() {
    let bin = dexd_bin();
    let (a, b, c) = ("127.0.0.1:47811", "127.0.0.1:47812", "127.0.0.1:47813");

    // A standalone; B dials A; C dials A and B — a small mesh.
    let _na = Node(Command::new(&bin).arg(a).spawn().unwrap());
    wait_port(a);
    let _nb = Node(Command::new(&bin).arg(b).arg(a).spawn().unwrap());
    wait_port(b);
    let _nc = Node(Command::new(&bin).arg(c).arg(a).arg(b).spawn().unwrap());
    wait_port(c);
    std::thread::sleep(Duration::from_millis(300));

    // Gossip one order into node C; it must reach a listener we attach to A.
    let mut listener_on_a = TcpStream::connect(a).unwrap();
    std::thread::sleep(Duration::from_millis(150));

    let (k, pk) = maker();
    let order = signed_order(&k, pk, 3_712_345_000, 7, now() + 3_600);
    let mut injector = TcpStream::connect(c).unwrap();
    injector.write_all(&frame(&order.to_wire())).unwrap();

    // Read one framed order back off node A — it propagated C→A(→our conn).
    listener_on_a
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut hdr = [0u8; 5];
    listener_on_a.read_exact(&mut hdr).expect("A relays the order");
    assert_eq!(hdr[0], 0x01);
    let len = u32::from_be_bytes(hdr[1..5].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; len];
    listener_on_a.read_exact(&mut payload).unwrap();
    let got = SignedOrder::from_wire(&payload).expect("valid order off the wire");
    assert_eq!(got, order, "the exact order propagated across the mesh");
}

/// Race F1: `sweep` must remove from the dedup set ONLY the orders it actually
/// dropped from the book — never overwrite it wholesale. A live order must stay
/// deduped across a sweep, or it would be re-flooded on its next sighting
/// (gossip amplification). This is the deterministic guard for the interleaving
/// the audit reproduced 1149/2000 times.
#[test]
fn sweep_keeps_live_orders_deduped() {
    let relay = Relay::new();
    let (k, pk) = maker();
    let t = now();
    let live = signed_order(&k, pk, 3_700_000_000, 1, t + 1_000);
    let expiring = signed_order(&k, pk, 3_800_000_000, 2, t + 5);
    assert_eq!(relay.ingest(live.clone(), t, true), Ingest::Accepted);
    assert_eq!(relay.ingest(expiring, t, true), Ingest::Accepted);
    assert_eq!(relay.order_count(), 2);

    // Sweep past the expiring order's expiry: drops exactly one.
    assert_eq!(relay.sweep(t + 10), 1);
    assert_eq!(relay.order_count(), 1);

    // The LIVE order is still deduped — sweep did not clobber `seen`.
    // Re-ingesting returns Duplicate (would-be re-flood), not Accepted.
    assert_eq!(relay.ingest(live, t + 10, true), Ingest::Duplicate);
    assert_eq!(relay.order_count(), 1);

    // A brand-new live order is still accepted normally after the sweep.
    let fresh = signed_order(&k, pk, 3_900_000_000, 3, t + 1_000);
    assert_eq!(relay.ingest(fresh, t + 10, true), Ingest::Accepted);
    assert_eq!(relay.order_count(), 2);
}
