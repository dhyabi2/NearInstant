//! Block 9a battery: every ceremony driven by two REAL independent parties
//! on separate threads, exchanging only framed bytes — no shared maps.
//! Both sides must independently arrive at identical, verified outputs.

use std::collections::BTreeMap;
use std::thread;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use rand::rngs::OsRng;
use rand::RngCore;

use nano_ceremony::block::{StateBlock, Subtype};
use signing::adaptor::{complete_presignature, extract_secret, verify_presignature};
use signing::{keys, Identifier};
use transport::ceremonies::{
    adaptor_presign_over_wire, clsag_cosign_over_wire, sign_block_over_wire, CosignRole,
};
use transport::{loopback, recv_frame, send_frame, tag, WireError};

fn keygen() -> (
    Vec<(Identifier, keys::KeyPackage)>,
    keys::PublicKeyPackage,
    [u8; 32],
) {
    let (shares, pubkeys) =
        keys::generate_with_dealer(2, 2, keys::IdentifierList::Default, &mut OsRng).unwrap();
    let parties: Vec<_> = shares
        .into_iter()
        .map(|(id, s)| (id, keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let account: [u8; 32] = pubkeys
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    (parties, pubkeys, account)
}

fn test_block(account: [u8; 32]) -> StateBlock {
    StateBlock {
        account,
        previous: [7; 32],
        representative: account,
        balance: 42,
        link: [9; 32],
        subtype: Subtype::Send,
    }
}

#[test]
fn framing_round_trips_and_rejects_wrong_tags() {
    let (a, b) = loopback();
    send_frame(&a, tag::COMMITMENTS, b"hello").unwrap();
    assert_eq!(recv_frame(&b, tag::COMMITMENTS).unwrap(), b"hello");

    send_frame(&b, tag::SIG_SHARE, b"x").unwrap();
    assert_eq!(
        recv_frame(&a, tag::COMMITMENTS),
        Err(WireError::UnexpectedMessage { expected: tag::COMMITMENTS, got: tag::SIG_SHARE })
    );
    drop(a);
    assert_eq!(recv_frame(&b, tag::SIG_SHARE), Err(WireError::Closed));
}

#[test]
fn two_party_keygen_across_threads() {
    use transport::ceremonies::keygen_over_wire;

    let alice_id = Identifier::try_from(1u16).unwrap();
    let bob_id = Identifier::try_from(2u16).unwrap();
    let (wa, wb) = loopback();

    let a = thread::spawn(move || keygen_over_wire(&wa, alice_id, bob_id).unwrap());
    let b = thread::spawn(move || keygen_over_wire(&wb, bob_id, alice_id).unwrap());
    let (a_kp, a_pubkeys) = a.join().unwrap();
    let (b_kp, b_pubkeys) = b.join().unwrap();

    // Both derive the identical joint account key.
    let a_account: [u8; 32] = a_pubkeys.verifying_key().serialize().unwrap().try_into().unwrap();
    let b_account: [u8; 32] = b_pubkeys.verifying_key().serialize().unwrap().try_into().unwrap();
    assert_eq!(a_account, b_account);

    // And each holds a distinct share that signs under the joint key.
    let block = test_block(a_account);
    let block_b = block.clone();
    let hash = block.hash();
    let (wa, wb) = loopback();
    let acct = a_account;
    let a = thread::spawn(move || {
        sign_block_over_wire(&wa, &block, &a_kp, &a_pubkeys).unwrap()
    });
    let b = thread::spawn(move || {
        sign_block_over_wire(&wb, &block_b, &b_kp, &b_pubkeys).unwrap()
    });
    let (sa, sb) = (a.join().unwrap(), b.join().unwrap());
    assert_eq!(sa, sb);
    assert!(signing::nano_verify::verify(&acct, &hash, &sa));
}

#[test]
fn two_party_keygen_over_a_real_websocket() {
    use std::net::TcpListener;
    use transport::ceremonies::keygen_over_wire;
    use transport::ws::WsWire;

    // A real server socket on localhost (plain ws:// — TLS terminates at a
    // proxy in deployment; the Wire only ever sees plaintext framing).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let alice_id = Identifier::try_from(1u16).unwrap();
    let bob_id = Identifier::try_from(2u16).unwrap();

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let wb = WsWire::accept(stream).unwrap();
        keygen_over_wire(&wb, bob_id, alice_id).unwrap()
    });
    let client = thread::spawn(move || {
        let wa = WsWire::connect(&format!("ws://{addr}/ws")).unwrap();
        keygen_over_wire(&wa, alice_id, bob_id).unwrap()
    });

    let (b_kp, b_pubkeys) = server.join().unwrap();
    let (a_kp, a_pubkeys) = client.join().unwrap();

    // Both parties derive the identical joint key over the WebSocket.
    let a_account: [u8; 32] = a_pubkeys.verifying_key().serialize().unwrap().try_into().unwrap();
    let b_account: [u8; 32] = b_pubkeys.verifying_key().serialize().unwrap().try_into().unwrap();
    assert_eq!(a_account, b_account);

    // And the two shares jointly sign a block valid under that key.
    let block = test_block(a_account);
    let (wa, wb) = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            WsWire::accept(stream).unwrap()
        });
        let client = WsWire::connect(&format!("ws://{addr}/ws")).unwrap();
        (client, server.join().unwrap())
    };
    let block_b = block.clone();
    let hash = block.hash();
    let acct = a_account;
    let a = thread::spawn(move || sign_block_over_wire(&wa, &block, &a_kp, &a_pubkeys).unwrap());
    let b = thread::spawn(move || sign_block_over_wire(&wb, &block_b, &b_kp, &b_pubkeys).unwrap());
    let (sa, sb) = (a.join().unwrap(), b.join().unwrap());
    assert_eq!(sa, sb);
    assert!(signing::nano_verify::verify(&acct, &hash, &sa));
}


#[test]
fn joint_block_signing_across_threads() {
    let (parties, pubkeys, account) = keygen();
    let block = test_block(account);
    let (wa, wb) = loopback();

    let mut handles = Vec::new();
    for ((_, kp), wire) in parties.into_iter().zip([wa, wb]) {
        let pubkeys = pubkeys.clone();
        let block = block.clone();
        handles.push(thread::spawn(move || {
            sign_block_over_wire(&wire, &block, &kp, &pubkeys).unwrap()
        }));
    }
    let sigs: Vec<[u8; 64]> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(sigs[0], sigs[1], "both parties hold the identical signature");
    assert!(signing::nano_verify::verify(&account, &block.hash(), &sigs[0]));
}

#[test]
fn adaptor_presign_across_threads_full_lifecycle() {
    let (parties, pubkeys, account) = keygen();
    let block = test_block(account);
    let x = Scalar::from_bytes_mod_order_wide(&[21u8; 64]);
    let t = (&x * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let (wa, wb) = loopback();

    let mut handles = Vec::new();
    for ((_, kp), wire) in parties.into_iter().zip([wa, wb]) {
        let pubkeys = pubkeys.clone();
        let block = block.clone();
        handles.push(thread::spawn(move || {
            adaptor_presign_over_wire(&wire, &block, &t, &kp, &pubkeys).unwrap()
        }));
    }
    let presigs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(presigs[0], presigs[1]);

    // Full atomic lifecycle on the wire-produced pre-signature.
    verify_presignature(&presigs[0], &account, &block.hash()).unwrap();
    let sig = complete_presignature(&presigs[0], &x.to_bytes()).unwrap();
    assert!(signing::nano_verify::verify(&account, &block.hash(), &sig));
    assert_eq!(extract_secret(&presigs[0], &sig).unwrap(), x.to_bytes());
}

#[test]
fn clsag_cosign_across_threads() {
    use monero_side::cosign::{musig_threshold_keys, StateSpend};
    use monero_side::isolation::{
        aggregate_spend, commitment, receiver_key_offset, sender_one_time_key, shared_view_key,
    };

    fn rand_scalar() -> Scalar {
        let mut w = [0u8; 64];
        OsRng.fill_bytes(&mut w);
        Scalar::from_bytes_mod_order_wide(&w)
    }

    // Joint XMR account + funded output (as in the Block 3 battery).
    let mut ctx = [0u8; 32];
    OsRng.fill_bytes(&mut ctx);
    let a = rand_scalar();
    let b = rand_scalar();
    let mut spend_pubs = vec![
        (&a * ED25519_BASEPOINT_TABLE).compress().to_bytes(),
        (&b * ED25519_BASEPOINT_TABLE).compress().to_bytes(),
    ];
    spend_pubs.sort();
    let joint = aggregate_spend(ctx, &spend_pubs).unwrap();
    let mut va = [0u8; 32];
    let mut vb = [0u8; 32];
    OsRng.fill_bytes(&mut va);
    OsRng.fill_bytes(&mut vb);
    let view_key = shared_view_key(ctx, &va, &vb);
    let vs = Option::<Scalar>::from(Scalar::from_canonical_bytes(view_key)).unwrap();
    let view_pub = (&vs * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let r = rand_scalar().to_bytes();
    let (tx_pub, output_key) = sender_one_time_key(&r, &view_pub, &joint, 0).unwrap();
    let key_offset = receiver_key_offset(&view_key, &tx_pub, &joint, 0, &output_key).unwrap();
    let amount = 500_000u64;
    let mask = rand_scalar().to_bytes();
    let mut ring = Vec::new();
    for i in 0..6 {
        if i == 2 {
            ring.push([output_key, commitment(&mask, amount).unwrap()]);
        } else {
            ring.push([
                (&rand_scalar() * ED25519_BASEPOINT_TABLE).compress().to_bytes(),
                commitment(&rand_scalar().to_bytes(), OsRng.next_u64()).unwrap(),
            ]);
        }
    }
    let mut msg = [0u8; 32];
    OsRng.fill_bytes(&mut msg);
    let spend = StateSpend {
        ring,
        ring_indices: (1..=6).collect(),
        real_index: 2,
        key_offset,
        mask,
        amount,
        pseudo_mask: rand_scalar().to_bytes(),
        msg,
    };

    let ka = musig_threshold_keys(ctx, &a.to_bytes(), &spend_pubs).unwrap();
    let kb = musig_threshold_keys(ctx, &b.to_bytes(), &spend_pubs).unwrap();
    let (pa, pb) = (ka.params().i(), kb.params().i());
    let (wa, wb) = loopback();

    let mut handles = Vec::new();
    for (keys, their, wire, role) in [(ka, pb, wa, CosignRole::Taker), (kb, pa, wb, CosignRole::Maker)] {
        let spend = StateSpend {
            ring: spend.ring.clone(),
            ring_indices: spend.ring_indices.clone(),
            real_index: spend.real_index,
            key_offset: spend.key_offset,
            mask: spend.mask,
            amount: spend.amount,
            pseudo_mask: spend.pseudo_mask,
            msg: spend.msg,
        };
        handles.push(thread::spawn(move || {
            clsag_cosign_over_wire(&wire, &spend, keys, their, role).unwrap()
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let (clsag_taker, image_a, pseudo_a) = &results[0];
    let (clsag_maker, image_b, pseudo_b) = &results[1];
    assert_eq!(image_a, image_b, "identical joint key image on both sides");
    assert_eq!(pseudo_a, pseudo_b);
    // Audit #2: only the taker gets a broadcastable CLSAG; the maker gets None.
    assert!(clsag_taker.is_some(), "taker completes");
    assert!(clsag_maker.is_none(), "maker must NOT obtain a broadcastable CLSAG");
    assert!(monero_side::cosign::verify_clsag(
        clsag_taker.as_ref().unwrap(), &spend.ring, image_a, pseudo_a, &spend.msg
    ));
}

/// A corrupted counterparty share is detected by the driver (aggregate
/// verification), not silently returned.
#[test]
fn corrupted_wire_share_is_rejected() {
    let (parties, pubkeys, account) = keygen();
    let block = test_block(account);
    let (wa, wb) = loopback();

    let mut it = parties.into_iter();
    let (_, kp_a) = it.next().unwrap();
    let (_, kp_b) = it.next().unwrap();
    let pk_a = pubkeys.clone();
    let block_a = block.clone();
    let honest = thread::spawn(move || sign_block_over_wire(&wa, &block_a, &kp_a, &pk_a));

    // The adversary follows round 1 honestly, then sends a garbage share.
    let (_nonces, my_comms) = signing::round1::commit(kp_b.signing_share(), &mut OsRng);
    send_frame(&wb, tag::COMMITMENTS, &my_comms.serialize().unwrap()).unwrap();
    let _their_comms = recv_frame(&wb, tag::COMMITMENTS).unwrap();
    let garbage = signing::round2::SignatureShare::deserialize(&[7u8; 32]).unwrap();
    send_frame(&wb, tag::SIG_SHARE, &garbage.serialize()).unwrap();
    let _ = recv_frame(&wb, tag::SIG_SHARE);

    assert_eq!(honest.join().unwrap(), Err(WireError::BadContribution));
    let _ = BTreeMap::<u8, u8>::new();
}

/// The same adaptor ceremony over REAL localhost TCP sockets — listener and
/// connector on separate threads, identical verified pre-signature.
#[test]
fn adaptor_presign_over_real_tcp() {
    use std::net::TcpListener;
    use transport::tcp::TcpWire;

    let (parties, pubkeys, account) = keygen();
    let block = test_block(account);
    let x = Scalar::from_bytes_mod_order_wide(&[33u8; 64]);
    let t = (&x * ED25519_BASEPOINT_TABLE).compress().to_bytes();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let mut it = parties.into_iter();
    let (_, kp_a) = it.next().unwrap();
    let (_, kp_b) = it.next().unwrap();

    let pk = pubkeys.clone();
    let blk = block.clone();
    let server = thread::spawn(move || {
        let wire = TcpWire::accept(&listener).unwrap();
        adaptor_presign_over_wire(&wire, &blk, &t, &kp_a, &pk).unwrap()
    });
    let pk2 = pubkeys.clone();
    let blk2 = block.clone();
    let client = thread::spawn(move || {
        let wire = TcpWire::connect(addr).unwrap();
        adaptor_presign_over_wire(&wire, &blk2, &t, &kp_b, &pk2).unwrap()
    });

    let ps_a = server.join().unwrap();
    let ps_b = client.join().unwrap();
    assert_eq!(ps_a, ps_b, "identical pre-signature across a real socket");
    verify_presignature(&ps_a, &account, &block.hash()).unwrap();
    let sig = complete_presignature(&ps_a, &x.to_bytes()).unwrap();
    assert!(signing::nano_verify::verify(&account, &block.hash(), &sig));
}

#[test]
fn ws_accept_enforces_origin_allowlist() {
    use std::io::Write as _;
    use std::net::{TcpListener, TcpStream};
    use transport::ws::WsWire;

    fn write_handshake(sock: &mut TcpStream, origin: Option<&str>) {
        let origin_line = match origin {
            Some(o) => format!("Origin: {o}\r\n"),
            None => String::new(),
        };
        let req = format!(
            "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{origin_line}\r\n"
        );
        sock.write_all(req.as_bytes()).unwrap();
    }

    let allowed = || vec!["https://good.example".to_string()];

    // Disallowed origin → refused.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let srv = thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        assert!(WsWire::accept_with_origin(s, &allowed()).is_err());
    });
    write_handshake(&mut TcpStream::connect(addr).unwrap(), Some("https://evil.example"));
    srv.join().unwrap();

    // Allowed origin → accepted.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let srv = thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        assert!(WsWire::accept_with_origin(s, &allowed()).is_ok());
    });
    write_handshake(&mut TcpStream::connect(addr).unwrap(), Some("https://good.example"));
    srv.join().unwrap();

    // No Origin (non-browser client) → admitted (still token-gated by caller).
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let srv = thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        assert!(WsWire::accept_with_origin(s, &allowed()).is_ok());
    });
    write_handshake(&mut TcpStream::connect(addr).unwrap(), None);
    srv.join().unwrap();
}

/// The REAL 2-of-2 DKG runs unchanged over MailboxWire — the async,
/// censorship-resistant, relay-mediated transport (R20) — proving the ceremony
/// is transport-agnostic: both parties, on separate threads, talking only
/// through a shared dumb in-memory relay, derive the identical joint account.
#[test]
fn two_party_keygen_over_mailbox_relay() {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use transport::ceremonies::keygen_over_wire;
    use transport::mailbox::{derive, MailboxWire, Relay};

    #[derive(Default)]
    struct MemRelay { store: Mutex<HashMap<(String, u64), Vec<u8>>> }
    impl Relay for MemRelay {
        fn post(&self, m: &str, s: u64, b: &[u8]) -> Result<(), String> {
            self.store.lock().unwrap().insert((m.to_string(), s), b.to_vec()); Ok(())
        }
        fn fetch(&self, m: &str, s: u64) -> Result<Option<Vec<u8>>, String> {
            Ok(self.store.lock().unwrap().get(&(m.to_string(), s)).cloned())
        }
    }
    struct Shared(Arc<MemRelay>);
    impl Relay for Shared {
        fn post(&self, m: &str, s: u64, b: &[u8]) -> Result<(), String> { self.0.post(m, s, b) }
        fn fetch(&self, m: &str, s: u64) -> Result<Option<Vec<u8>>, String> { self.0.fetch(m, s) }
    }

    let relay = Arc::new(MemRelay::default());
    let shared_secret = [0x5Au8; 32]; // the R18 rendezvous seed both parties share
    let (a_send, a_recv, key) = derive(&shared_secret, true);
    let (b_send, b_recv, _k) = derive(&shared_secret, false);
    let poll = (Duration::from_millis(5), Duration::from_secs(10));

    let wa = MailboxWire::new(vec![Box::new(Shared(relay.clone()))], a_send, a_recv, key)
        .with_polling(poll.0, poll.1);
    let wb = MailboxWire::new(vec![Box::new(Shared(relay.clone()))], b_send, b_recv, key)
        .with_polling(poll.0, poll.1);

    let alice_id = Identifier::try_from(1u16).unwrap();
    let bob_id = Identifier::try_from(2u16).unwrap();
    let a = thread::spawn(move || keygen_over_wire(&wa, alice_id, bob_id).unwrap());
    let b = thread::spawn(move || keygen_over_wire(&wb, bob_id, alice_id).unwrap());
    let (_a_kp, a_pubkeys) = a.join().unwrap();
    let (_b_kp, b_pubkeys) = b.join().unwrap();

    let a_account: [u8; 32] = a_pubkeys.verifying_key().serialize().unwrap().try_into().unwrap();
    let b_account: [u8; 32] = b_pubkeys.verifying_key().serialize().unwrap().try_into().unwrap();
    assert_eq!(a_account, b_account, "the real DKG over the relay yields the identical joint account");
}
