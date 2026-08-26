//! `swapper` — the supervised settlement executor (P0 #13/#14/#15/#17).
//!
//! Runs ONE side of a two-party atomic swap over a real TCP wire + real Nano
//! RPC nodes + the REAL Monero leg (`swap_executor::MoneroLeg`).
//!
//! THIS BINARY MOVES REAL NANO + XMR VALUE. It refuses to run unless you pass
//! `--live` and point it at a funded wallet.
//!
//! Maker side (Bob, sells XMR, receives XNO):
//!   swapper --role maker --listen 0.0.0.0:47999 \
//!     --nano https://rpc.nano.to --nano <2nd-node> \
//!     --chunk <raw> --x <bob-spend-secret-hex> --ctx <hex> --view <hex> --net mainnet \
//!     --bob-dest <hex> --open-link <hex> \
//!     --monero <daemon-url>... --wallet-rpc <wallet-rpc-json-rpc-url> --wallet-password <pw> \
//!     --live
//!
//! Taker side (Alice, sells XNO, receives XMR):
//!   swapper --role taker --connect <maker>:47999 \
//!     --nano https://rpc.nano.to --nano <2nd-node> \
//!     --chunk <raw> --x <alice-spend-secret-hex> --ctx <hex> --view <hex> --net mainnet \
//!     --open-link <hex> --sweep-dest <alice-xmr-address> --monero <daemon-url>... --live

use std::net::TcpListener;

use nano_ceremony::broadcast::{frontier_balance_quorum, NanoNode, RpcNode};
use nano_ceremony::{address, work};
use signing::{SigningKey, VerifyingKey};
use swap_executor::{run_alice_with_reserve, run_bob, MoneroLeg, MoneroNet, ReserveProof, XmrParty, XmrSide};
use transport::tcp::TcpWire;
use transport::Wire;

fn parse_hex32(name: &str, s: &str) -> [u8; 32] {
    let bytes = hex::decode(s.trim()).unwrap_or_else(|e| {
        eprintln!("{name}: not valid hex ({e})");
        std::process::exit(2);
    });
    bytes
        .try_into()
        .unwrap_or_else(|_| {
            eprintln!("{name}: must be 32 bytes (64 hex chars)");
            std::process::exit(2);
        })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut role: Option<String> = None;
    let mut sell: Option<String> = None;
    let mut listen: Option<String> = None;
    let mut connect: Option<String> = None;
    let mut nano: Vec<String> = Vec::new();
    let mut chunk: u128 = 0;
    let mut x: Option<[u8; 32]> = None;
    let mut ctx: Option<[u8; 32]> = None;
    let mut view: Option<[u8; 32]> = None;
    let mut net = "stagenet".to_string();
    let mut bob_dest: Option<[u8; 32]> = None;
    let mut open_link: Option<[u8; 32]> = None;
    let mut monero_urls: Vec<String> = Vec::new();
    let mut wallet_rpc: Option<String> = None;
    let mut wallet_password: Option<String> = None;
    let mut sweep_dest: Option<String> = None;
    let mut live = false;
    let mut work_threshold = work::THRESHOLD_SEND;
    let mut reserve_address: Option<String> = None;
    let mut reserve_message: Option<String> = None;
    let mut reserve_proof: Option<String> = None;
    let mut reserve_amount: u128 = 0;
    let mut serve: Option<String> = None;
    let mut token: Option<String> = None;
    let mut ws_origins: Vec<String> = Vec::new();
    let mut nano_seed: Option<[u8; 32]> = None;
    let mut checkpoint_arg: Option<String> = None;
    let mut transcript_arg: Option<String> = None;
    let mut fund_rpc: Option<String> = None;
    let mut fund_wallet: Option<String> = None;
    let mut fund_source: Option<String> = None;
    let mut fund_key: Option<[u8; 32]> = None;
    let mut resume_path: Option<String> = None;
    let mut no_checkpoint = false;

    let mut i = 0;
    while i < args.len() {
        let (k, v) = (
            args[i].clone(),
            args.get(i + 1).cloned().unwrap_or_default(),
        );
        match k.as_str() {
            "--role" => role = Some(v),
            "--sell" => sell = Some(v),
            "--listen" => listen = Some(v),
            "--connect" => connect = Some(v),
            "--nano" => nano.push(v),
            "--chunk" => chunk = v.parse().unwrap_or_else(|_| usage_exit("--chunk")),
            "--x" => x = Some(parse_hex32("--x", &v)),
            "--ctx" => ctx = Some(parse_hex32("--ctx", &v)),
            "--view" => view = Some(parse_hex32("--view", &v)),
            "--net" => net = v,
            "--bob-dest" => bob_dest = Some(parse_hex32("--bob-dest", &v)),
            "--open-link" => open_link = Some(parse_hex32("--open-link", &v)),
            "--monero" => monero_urls.push(v),
            "--wallet-rpc" => wallet_rpc = Some(v),
            "--wallet-password" => wallet_password = Some(v),
            "--sweep-dest" => sweep_dest = Some(v),
            "--reserve-address" => reserve_address = Some(v),
            "--reserve-message" => reserve_message = Some(v),
            "--reserve-proof" => reserve_proof = Some(v),
            "--reserve-amount" => {
                reserve_amount = v.parse().unwrap_or_else(|_| usage_exit("--reserve-amount"))
            }
            "--work-threshold" => {
                work_threshold = u64::from_str_radix(v.trim_start_matches("0x"), 16)
                    .unwrap_or_else(|_| usage_exit("--work-threshold"))
            }
            "--serve" => serve = Some(v),
            "--token" => token = Some(v),
            "--ws-origin" => ws_origins.push(v),
            "--nano-seed" => nano_seed = Some(parse_hex32("--nano-seed", &v)),
            "--fund-rpc" => fund_rpc = Some(v),
            "--fund-wallet" => fund_wallet = Some(v),
            "--fund-source" => fund_source = Some(v),
            "--fund-key" => fund_key = Some(parse_hex32("--fund-key", &v)),
            "--checkpoint" => checkpoint_arg = Some(v),
            "--transcript" => transcript_arg = Some(v),
            "--resume" => resume_path = Some(v),
            "--no-checkpoint" => {
                no_checkpoint = true;
                i += 1;
                continue;
            }
            "--live" => {
                live = true;
                i += 1;
                continue;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            _ => usage_exit(&format!("unknown arg {k}")),
        }
        i += 2;
    }

    if !live {
        eprintln!("refusing to run without --live (this binary moves REAL Nano + XMR value).");
        eprintln!("review the command line, fund both wallets, then re-run with --live.");
        std::process::exit(2);
    }

    // ---- common config (serve bridge AND direct CLI) ---------------------
    if monero_urls.is_empty() {
        usage_exit("--monero <daemon-url>... required (repeat for a confirmation quorum)");
    }
    let net = match net.as_str() {
        "mainnet" => MoneroNet::Mainnet,
        "stagenet" => MoneroNet::Stagenet,
        _ => usage_exit("--net must be mainnet or stagenet"),
    };
    // Real value on mainnet must never trust a single daemon's view of
    // maturity — the Monero mirror of the Nano quorum>=2 rule.
    if live && matches!(net, MoneroNet::Mainnet) && monero_urls.len() < 2 {
        usage_exit(
            "--live on mainnet needs >=2 --monero daemons from independent operators \
             (e.g. https://xmr-node.cakewallet.com:18081 and https://node.sethforprivacy.com)",
        );
    }
    let key = std::env::var("NANO_RPC_KEY").unwrap_or_default();
    let nodes: Vec<RpcNode> = nano
        .iter()
        .map(|u| {
            if key.is_empty() {
                RpcNode::new(u)
            } else {
                RpcNode::with_key(u, &key)
            }
        })
        .collect();
    let node_refs: Vec<&dyn NanoNode> = nodes.iter().map(|n| n as &dyn NanoNode).collect();
    let open_link = open_link.unwrap_or([0xAA; 32]);

    let xmr: Box<dyn XmrSide> = Box::new(
        MoneroLeg::with_quorum(
            &monero_urls,
            net,
            sweep_dest.clone(),
            wallet_rpc.clone(),
            wallet_password.clone(),
        )
        .expect("construct real Monero leg"),
    );

    // Key material is optional: a pure check-reserve bridge needs none; a
    // settlement session does.
    let party: Option<XmrParty> = x.map(|spend_secret| XmrParty {
        context: ctx.unwrap_or([0u8; 32]),
        spend_secret,
        view_contribution: view.unwrap_or([0u8; 32]),
        net,
    });

    // Crash-safe checkpoint file: ON by default (this binary moves real value;
    // a crash mid-settle must be resumable). `--no-checkpoint` opts out.
    let checkpoint: Option<std::path::PathBuf> = if no_checkpoint {
        None
    } else {
        Some(checkpoint_arg.map(std::path::PathBuf::from).unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            std::path::PathBuf::from(home).join(".xnoxmr").join("swap.chkpt.json")
        }))
    };

    // R2 transcript: on by default next to the checkpoint (public evidence of
    // the settlement; holds no secrets). `--transcript <path>` overrides.
    let transcript: Option<std::path::PathBuf> = if no_checkpoint {
        transcript_arg.map(std::path::PathBuf::from)
    } else {
        Some(transcript_arg.map(std::path::PathBuf::from).unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            std::path::PathBuf::from(home).join(".xnoxmr").join("swap.transcript.jsonl")
        }))
    };

    // Resume mode: finish an interrupted settlement from its checkpoint file.
    // Needs only this side's own key material — never the counterparty.
    if let Some(rp) = resume_path {
        let raw = std::fs::read_to_string(&rp).unwrap_or_else(|e| {
            eprintln!("--resume {rp}: {e}");
            std::process::exit(2);
        });
        let secret = x.unwrap_or_else(|| usage_exit("--resume needs --x (your spend secret)"));
        let mut progress = |m: &str| eprintln!("[resume] {m}");
        let outcome = if let Ok(cp) = swap_executor::AliceCheckpoint::from_json(&raw) {
            swap_executor::resume_alice(&node_refs, &*xmr, &secret, &cp, &mut progress).map(|x| {
                eprintln!("resumed: extracted secret {} and swept XMR.", hex::encode(x));
            })
        } else if let Ok(cp) = swap_executor::BobCheckpoint::from_json(&raw) {
            swap_executor::resume_bob(&node_refs, &secret, &cp, 2, 20, &mut progress)
                .map(|()| eprintln!("resumed: XNO leg settled."))
        } else {
            eprintln!("--resume {rp}: not a valid checkpoint file");
            std::process::exit(2);
        };
        match outcome {
            Ok(()) => {
                let _ = std::fs::remove_file(&rp);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("resume failed (checkpoint kept): {e:?}");
                std::process::exit(1);
            }
        }
    }

    let reserve = match (reserve_address, reserve_message, reserve_proof) {
        (Some(address), Some(message), Some(proof)) if reserve_amount > 0 => {
            Some(ReserveProof { address, amount: reserve_amount, message, proof })
        }
        _ => None,
    };

    let session = build_session(
        role.as_deref(),
        sell.as_deref(),
        listen.clone(),
        connect.clone(),
        chunk,
        party,
        bob_dest,
        open_link,
        work_threshold,
        reserve,
        checkpoint.clone(),
        transcript,
        match (&fund_rpc, fund_wallet, fund_source) {
            (Some(r), Some(w), Some(s)) => Some((r.clone(), w, s)),
            (_, None, None) => None,
            _ => usage_exit("--fund-rpc, --fund-wallet and --fund-source go together"),
        },
        match (&fund_rpc, fund_key) {
            (Some(r), Some(k)) => Some((r.clone(), k)),
            (_, None) => None,
            _ => usage_exit("--fund-key needs --fund-rpc"),
        },
    );

    // Wallet bridge: a localhost-only JSON-RPC WebSocket the browser drives —
    // the browser is a thin UI, keys stay in this native helper (problem 3).
    if let Some(addr) = serve {
        let tok = token.unwrap_or_else(rand_token);
        let nano_account = nano_seed.map(|seed| nano_account_from_seed(seed));
        if let Some((_, a)) = &nano_account {
            eprintln!("Nano account: {a}");
        } else {
            eprintln!("no --nano-seed: Nano address/balance RPCs disabled");
        }
        eprintln!("pairing token: {tok}");
        serve_bridge(
            &addr,
            &tok,
            &*xmr,
            &node_refs,
            session.as_ref(),
            &ws_origins,
            nano_account,
            checkpoint.as_deref(),
        );
    }

    // Direct CLI mode: settle once and exit.
    let session = session.expect("--role maker|taker required (and --listen/--connect + --x)");
    if node_refs.len() < 2 {
        eprintln!("need >= 2 independent --nano nodes (multi-node confirmation).");
        std::process::exit(2);
    }
    run_session(&session, &node_refs, &*xmr, &mut |m| eprintln!("swapper {m}"))
        .unwrap_or_else(|e| {
            eprintln!("session failed: {e}");
            std::process::exit(1);
        });
}

/// Network topology role: who binds/listens vs who connects.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Maker,
    Taker,
}

/// Which asset this party SELLS — decides which half of the atomic swap it
/// runs (XNO-seller = the run_alice half, XMR-seller = the run_bob half),
/// independent of the network role. The two peers must sell opposite assets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sell {
    Xno,
    Xmr,
}

/// Everything a settlement session needs, resolved once from the CLI.
struct Session {
    role: Role,
    sell: Sell,
    peer: String,
    chunk: u128,
    party: XmrParty,
    bob_dest: [u8; 32],
    open_link: [u8; 32],
    work_threshold: u64,
    reserve: Option<ReserveProof>,
    checkpoint: Option<std::path::PathBuf>,
    transcript: Option<std::path::PathBuf>,
    /// Dev/test funding source: (node RPC url, wallet id, source account).
    /// The taker funds the joint account mid-session through the node's
    /// wallet `send` RPC — only sensible on a dev network you control.
    fund: Option<(String, String, String)>,
    /// Raw-key funding: (node RPC url, private key). For nodes without the
    /// wallet RPC: our stack builds + signs the send itself, the node only
    /// supplies work and processes the block.
    fund_key: Option<(String, [u8; 32])>,
}

fn build_session(
    role: Option<&str>,
    sell: Option<&str>,
    listen: Option<String>,
    connect: Option<String>,
    chunk: u128,
    party: Option<XmrParty>,
    bob_dest: Option<[u8; 32]>,
    open_link: [u8; 32],
    work_threshold: u64,
    reserve: Option<ReserveProof>,
    checkpoint: Option<std::path::PathBuf>,
    transcript: Option<std::path::PathBuf>,
    fund: Option<(String, String, String)>,
    fund_key: Option<(String, [u8; 32])>,
) -> Option<Session> {
    let role = match role {
        Some("maker") => Role::Maker,
        Some("taker") => Role::Taker,
        _ => return None,
    };
    // Backward-compatible default: maker sells XMR, taker sells XNO (the
    // original hard-wired behaviour). `--sell xno|xmr` overrides it.
    let sell = match sell {
        Some("xno") => Sell::Xno,
        Some("xmr") => Sell::Xmr,
        None => match role {
            Role::Maker => Sell::Xmr,
            Role::Taker => Sell::Xno,
        },
        _ => usage_exit("--sell must be xno or xmr"),
    };
    let peer = match role {
        Role::Maker => listen?,
        Role::Taker => connect?,
    };
    let party = party?;
    // The XMR-seller receives XNO into `--bob-dest`; only that side needs it.
    let bob_dest = if sell == Sell::Xmr { bob_dest? } else { [0u8; 32] };
    Some(Session { role, sell, peer, chunk, party, bob_dest, open_link, work_threshold, reserve, checkpoint, transcript, fund, fund_key })
}

/// Fund the joint account from a raw private key: OUR stack builds and signs
/// the send state block; the node only supplies work (`work_generate`) and
/// validates it (`process`). Returns the send block's hash (the open_link).
/// Dev/rehearsal use — it moves whatever the key's account holds.
fn fund_with_key(rpc: &str, key_bytes: &[u8; 32], chunk: u128, joint: &[u8; 32]) -> Option<[u8; 32]> {
    let call = |body: serde_json::Value| -> Option<serde_json::Value> {
        match ureq::post(rpc).send_json(body) {
            Ok(r) => r.into_json().ok(),
            Err(e) => {
                eprintln!("fund_with_key RPC error: {e}");
                None
            }
        }
    };
    let key = SigningKey::deserialize(key_bytes).ok()?;
    let pubkey: [u8; 32] = VerifyingKey::from(&key).serialize().ok()?.try_into().ok()?;
    let source_addr = address::encode(&pubkey);

    let info = call(serde_json::json!({
        "action": "account_info", "account": source_addr, "representative": "true",
    }))?;
    let field = |k: &str| -> Option<&str> {
        info.get(k).and_then(|v| v.as_str()).or_else(|| {
            eprintln!("fund_with_key: account_info missing {k}: {info}");
            None
        })
    };
    let frontier: [u8; 32] = match hex::decode(field("frontier")?).ok().and_then(|b| b.try_into().ok()) {
        Some(f) => f,
        None => { eprintln!("fund_with_key: bad frontier hex"); return None; }
    };
    let balance: u128 = match field("balance")?.parse() {
        Ok(b) => b,
        Err(e) => { eprintln!("fund_with_key: bad balance: {e}"); return None; }
    };
    let rep = match address::decode(field("representative")?) {
        Some(r) => r,
        None => { eprintln!("fund_with_key: bad representative address"); return None; }
    };
    if balance < chunk {
        eprintln!("funder account holds {balance} raw < chunk {chunk}");
        return None;
    }

    let block = nano_ceremony::block::StateBlock {
        account: pubkey,
        previous: frontier,
        representative: rep,
        balance: balance - chunk,
        link: *joint,
        subtype: nano_ceremony::block::Subtype::Send,
    };
    let hash = block.hash();
    let sig = key.sign(&mut rand::rngs::OsRng, &hash);
    let sig_bytes: [u8; 64] = sig.serialize().ok()?.try_into().ok()?;
    if !signing::nano_verify::verify(&pubkey, &hash, &sig_bytes) {
        eprintln!("fund_with_key: our own send signature failed to verify");
        return None;
    }

    let work = call(serde_json::json!({
        "action": "work_generate", "hash": hex::encode_upper(block.work_root()),
    }))?;
    let work = work.get("work")?.as_str()?.to_string();

    eprintln!("funding joint account {} with {chunk} raw…", address::encode(joint));
    let resp = call(serde_json::json!({
        "action": "process", "json_block": "true", "subtype": "send",
        "block": {
            "type": "state",
            "account": source_addr,
            "previous": hex::encode_upper(frontier),
            "representative": address::encode(&rep),
            "balance": (balance - chunk).to_string(),
            "link": hex::encode_upper(joint),
            "signature": hex::encode_upper(sig_bytes),
            "work": work,
        },
    }))?;
    let accepted = resp.get("hash")?.as_str()?;
    eprintln!("funded: pending send {accepted}");
    hex::decode(accepted).ok()?.try_into().ok()
}

/// Run one settlement session. `nodes` must be >= 2 independent Nano nodes.
///
/// Network topology (who listens vs connects) is set by `role`; which HALF of
/// the atomic swap this party runs is set by `sell` — the XNO-seller always
/// runs the `run_alice` half (funds the joint account, sweeps XMR), the
/// XMR-seller always runs the `run_bob` half (locks XMR, reveals the secret).
/// The adaptor invariant is unchanged: the reveal is always on the XMR leg.
/// The two peers MUST sell opposite assets (the wire steps only line up then).
fn run_session(
    s: &Session,
    nodes: &[&dyn NanoNode],
    xmr: &dyn XmrSide,
    progress: &mut dyn FnMut(&str),
) -> Result<(), String> {
    if nodes.len() < 2 {
        return Err("need >= 2 independent --nano nodes".into());
    }
    // Establish the byte wire per network role.
    let wire = match s.role {
        Role::Maker => {
            let listener = TcpListener::bind(&s.peer).map_err(|e| format!("bind {}: {e}", s.peer))?;
            eprintln!("swapper[{:?}] listening on {} (chunk {}) — awaiting peer…", s.sell, s.peer, s.chunk);
            progress("Waiting for a peer to connect…");
            TcpWire::accept(&listener).map_err(|e| format!("accept: {e}"))?
        }
        Role::Taker => TcpWire::connect(&s.peer).map_err(|e| format!("connect {}: {e}", s.peer))?,
    };

    match s.sell {
        // ---- This party SELLS XMR → run the run_bob half ------------------
        Sell::Xmr => {
            run_bob(
                &wire, nodes, xmr, s.chunk, &s.party, s.bob_dest, s.open_link,
                s.work_threshold, 2, 20, s.checkpoint.as_deref(), s.transcript.as_deref(),
                progress,
            )
            .map_err(|e| format!("{e:?}"))?;
            eprintln!("swapper[sell-xmr] settled: XMR locked, XNO leg claimed.");
            Ok(())
        }
        // ---- This party SELLS XNO → run the run_alice half ----------------
        Sell::Xno => {
            eprintln!("sell-xno funders: fund(wallet)={} fund_key={}", s.fund.is_some(), s.fund_key.is_some());
            // Dev-net funder: sends the chunk into the joint account through the
            // node wallet RPC (or a raw key) once the DKG has created it.
            let mut funder_impl;
            let funder: Option<&mut dyn FnMut(&[u8; 32]) -> Option<[u8; 32]>> = match &s.fund {
                Some((rpc, wallet, source)) => {
                    let (rpc, wallet, source) = (rpc.clone(), wallet.clone(), source.clone());
                    let chunk = s.chunk;
                    funder_impl = move |account: &[u8; 32]| -> Option<[u8; 32]> {
                        let dest = address::encode(account);
                        eprintln!("funding joint account {dest} with {chunk} raw…");
                        let resp = ureq::post(&rpc)
                            .send_json(serde_json::json!({
                                "action": "send", "wallet": wallet, "source": source,
                                "destination": dest, "amount": chunk.to_string(),
                            }))
                            .ok()?
                            .into_json::<serde_json::Value>()
                            .ok()?;
                        let h = resp.get("block")?.as_str()?;
                        eprintln!("funded: pending send {h}");
                        hex::decode(h).ok()?.try_into().ok()
                    };
                    Some(&mut funder_impl)
                }
                None => None,
            };
            let mut key_funder_impl;
            let funder = match (&s.fund_key, funder) {
                (Some((rpc, key)), None) => {
                    let (rpc, key, chunk) = (rpc.clone(), *key, s.chunk);
                    key_funder_impl = move |account: &[u8; 32]| -> Option<[u8; 32]> {
                        fund_with_key(&rpc, &key, chunk, account)
                    };
                    Some(&mut key_funder_impl as &mut dyn FnMut(&[u8; 32]) -> Option<[u8; 32]>)
                }
                (_, f) => f,
            };
            let secret = run_alice_with_reserve(
                &wire, nodes, xmr, s.chunk, s.open_link, s.work_threshold, &s.party,
                s.reserve.as_ref(), s.checkpoint.as_deref(), s.transcript.as_deref(),
                funder, progress,
            )
            .map_err(|e| format!("{e:?}"))?;
            eprintln!("swapper[sell-xno] extracted secret {} and swept XMR.", hex::encode(secret));
            Ok(())
        }
    }
}

fn usage_exit(why: &str) -> ! {
    eprintln!("usage error: {why}");
    print_usage();
    std::process::exit(2);
}

/// A pairing token for the localhost wallet bridge. Not cryptographic — it
/// rides on top of the loopback-only bind (the real boundary) and is printed
/// so the operator can paste it into the browser's pairing prompt.
fn rand_token() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:016x}")
}

/// Derive a Nano account public key + `nano_…` address from a 32-byte seed.
fn nano_account_from_seed(seed: [u8; 32]) -> ([u8; 32], String) {
    let key = SigningKey::deserialize(&seed).expect("valid ed25519 seed");
    let vk = VerifyingKey::from(&key);
    let pubkey: [u8; 32] = vk.serialize().expect("serialize vk").try_into().expect("32 bytes");
    let addr = address::encode(&pubkey);
    (pubkey, addr)
}

/// Serve the local wallet bridge: a loopback-only WebSocket that accepts the
/// JSON-RPC the browser sends. Refuses to bind anything but loopback, since
/// this helper holds the user's keys and can move funds.
fn serve_bridge(
    listen: &str,
    token: &str,
    xmr: &dyn XmrSide,
    nodes: &[&dyn NanoNode],
    session: Option<&Session>,
    ws_origins: &[String],
    nano_account: Option<([u8; 32], String)>,
    checkpoint: Option<&std::path::Path>,
) -> ! {
    let listener = std::net::TcpListener::bind(listen).unwrap_or_else(|e| {
        eprintln!("bind {listen} failed: {e}");
        std::process::exit(2);
    });
    let la = listener.local_addr().expect("local addr");
    if !la.ip().is_loopback() {
        eprintln!("refusing to bind a non-loopback address for the wallet bridge");
        std::process::exit(2);
    }
    eprintln!(
        "wallet bridge on {la} — loopback only, token-authenticated{}",
        if ws_origins.is_empty() { "" } else { ", origin-checked" }
    );
    loop {
        let Ok((stream, _)) = listener.accept() else { continue };
        let ws = match transport::ws::WsWire::accept_with_origin(stream, ws_origins) {
            Ok(w) => w,
            Err(_) => continue,
        };
        serve_bridge_client(ws, token, xmr, nodes, session, nano_account.as_ref(), checkpoint);
    }
}

fn serve_bridge_client(
    ws: transport::ws::WsWire<std::net::TcpStream>,
    token: &str,
    xmr: &dyn XmrSide,
    nodes: &[&dyn NanoNode],
    session: Option<&Session>,
    nano_account: Option<&([u8; 32], String)>,
    checkpoint: Option<&std::path::Path>,
) {
    // First frame must be the pairing token; anything else closes the socket.
    match ws.recv() {
        Ok(auth) if String::from_utf8_lossy(&auth).trim() == token => {}
        _ => return,
    }
    loop {
        let req = match ws.recv() {
            Ok(r) => String::from_utf8_lossy(&r).into_owned(),
            Err(_) => return,
        };
        let op = serde_json::from_str::<serde_json::Value>(&req)
            .ok()
            .and_then(|v| v.get("op").and_then(|o| o.as_str()).map(|s| s.to_string()));

let resp = match op.as_deref() {
            Some("start") => run_and_stream(session, nodes, xmr, &ws),
            Some("nano_balance") => nano_balance(nodes, &req),
            Some("nano_address") => nano_address(nano_account),
            Some("session_info") => session_info(session),
            Some("checkpoint_status") => checkpoint_status(checkpoint),
            Some("resume") => resume_and_stream(checkpoint, session, nodes, xmr, &ws),
            Some("ping")
            | Some("check_reserve")
            | Some("xmr_address")
            | Some("xmr_balance") => swap_executor::handle_rpc(xmr, &req),
            Some(_) => {
                serde_json::json!({ "ok": false, "error": "unknown op" }).to_string()
            }
            None => serde_json::json!({ "ok": false, "error": "bad json" }).to_string(),
        };
        if ws.send(resp.into_bytes()).is_err() {
            return;
        }
    }
}

/// Handle a `start` op: if a session is configured, run it inline and stream
/// progress/`done`/`error` events over the bridge. Runs blocking on this
/// thread (the bridge serves one session at a time — fine for a local helper).
fn run_and_stream(
    session: Option<&Session>,
    nodes: &[&dyn NanoNode],
    xmr: &dyn XmrSide,
    ws: &transport::ws::WsWire<std::net::TcpStream>,
) -> String {
    let Some(s) = session else {
        return serde_json::json!({ "ok": false, "error": "no session configured (pass --role …)" })
            .to_string();
    };
    let mut progress = |m: &str| {
        let _ = ws.send(serde_json::json!({ "event": "progress", "msg": m }).to_string().into_bytes());
    };
    match run_session(s, nodes, xmr, &mut progress) {
        Ok(()) => serde_json::json!({ "ok": true, "event": "done" }).to_string(),
        Err(e) => serde_json::json!({ "ok": false, "event": "error", "error": e }).to_string(),
    }
}

/// Report the helper's own Nano account (`nano_…` address + public key hex),
/// or an error when the helper was started without `--nano-seed`.
fn nano_address(nano_account: Option<&([u8; 32], String)>) -> String {
    match nano_account {
        Some((pubkey, addr)) => serde_json::json!({
            "ok": true,
            "result": { "account": addr, "public": hex::encode(pubkey) },
        })
        .to_string(),
        None => serde_json::json!({ "ok": false, "error": "helper started without --nano-seed" })
            .to_string(),
    }
}

/// Report the swap this helper was configured to run (read-only): which coin
/// the user sells and receives, the per-chunk size in raw units, the peer
/// address, and the network role. `{"configured":false}` when the helper was
/// started without a session. The page shows this instead of a typed amount —
/// the real swap's parameters live in the helper, set at launch.
fn session_info(session: Option<&Session>) -> String {
    let Some(s) = session else {
        return serde_json::json!({ "ok": true, "result": { "configured": false } }).to_string();
    };
    let (sell, receive) = match s.sell {
        Sell::Xno => ("Nano", "Monero"),
        Sell::Xmr => ("Monero", "Nano"),
    };
    let role = match s.role {
        Role::Maker => "maker",
        Role::Taker => "taker",
    };
    serde_json::json!({
        "ok": true,
        "result": {
            "configured": true,
            "sell": sell,
            "receive": receive,
            "chunk_raw": s.chunk.to_string(),
            "peer": s.peer,
            "role": role,
        }
    })
    .to_string()
}

/// Report whether an interrupted settlement is waiting to be resumed
/// (`{"present":bool,"role":"taker"|"maker"|null}`), so the page can offer a
/// Resume button (R6).
fn checkpoint_status(checkpoint: Option<&std::path::Path>) -> String {
    let role = checkpoint
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|raw| {
            if swap_executor::AliceCheckpoint::from_json(&raw).is_ok() {
                Some("taker")
            } else if swap_executor::BobCheckpoint::from_json(&raw).is_ok() {
                Some("maker")
            } else {
                None
            }
        });
    serde_json::json!({ "ok": true, "result": { "present": role.is_some(), "role": role } })
        .to_string()
}

/// Handle a `resume` op: finish an interrupted settlement from the helper's
/// checkpoint file, streaming progress like `start`. Needs the session's key
/// material (`--role`/`--x`) — the checkpoint itself holds no secrets.
fn resume_and_stream(
    checkpoint: Option<&std::path::Path>,
    session: Option<&Session>,
    nodes: &[&dyn NanoNode],
    xmr: &dyn XmrSide,
    ws: &transport::ws::WsWire<std::net::TcpStream>,
) -> String {
    let Some(path) = checkpoint else {
        return serde_json::json!({ "ok": false, "error": "checkpointing disabled" }).to_string();
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return serde_json::json!({ "ok": false, "error": "no interrupted swap found" }).to_string();
    };
    let Some(s) = session else {
        return serde_json::json!({ "ok": false, "error": "no session configured (pass --role and --x to resume)" })
            .to_string();
    };
    let mut progress = |m: &str| {
        let _ = ws.send(serde_json::json!({ "event": "progress", "msg": m }).to_string().into_bytes());
    };
    let outcome = if let Ok(cp) = swap_executor::AliceCheckpoint::from_json(&raw) {
        swap_executor::resume_alice(nodes, xmr, &s.party.spend_secret, &cp, &mut progress).map(|_| ())
    } else if let Ok(cp) = swap_executor::BobCheckpoint::from_json(&raw) {
        swap_executor::resume_bob(nodes, &s.party.spend_secret, &cp, 2, 20, &mut progress)
    } else {
        return serde_json::json!({ "ok": false, "error": "checkpoint file is corrupt" }).to_string();
    };
    match outcome {
        Ok(()) => {
            let _ = std::fs::remove_file(path);
            serde_json::json!({ "ok": true, "event": "done" }).to_string()
        }
        Err(e) => serde_json::json!({ "ok": false, "event": "error", "error": format!("{e:?}") })
            .to_string(),
    }
}

/// Resolve a Nano account's live balance from the helper's node quorum
fn nano_balance(nodes: &[&dyn NanoNode], req: &str) -> String {
    let v: serde_json::Value = match serde_json::from_str(req) {
        Ok(v) => v,
        Err(_) => return serde_json::json!({ "ok": false, "error": "bad json" }).to_string(),
    };
    let err = |m: &str| serde_json::json!({ "ok": false, "error": m }).to_string();
    let Some(hexed) = v.get("account").and_then(|s| s.as_str()) else {
        return err("missing account");
    };
    let bytes = match hex::decode(hexed.trim()) {
        Ok(b) => b,
        Err(_) => return err("bad hex account"),
    };
    let Ok(acct) = <[u8; 32]>::try_from(bytes.as_slice()) else {
        return err("account must be 32 bytes");
    };
    match frontier_balance_quorum(nodes, &acct, 2) {
        Some(bal) => serde_json::json!({ "ok": true, "result": { "balance": bal.to_string() } })
            .to_string(),
        None => serde_json::json!({ "ok": true, "result": { "balance": null } }).to_string(),
    }
}

fn print_usage() {
    eprintln!(
        "swapper --role maker|taker [--sell xno|xmr] (--listen|--connect <addr>) --nano <url> [--nano <url>] \
         --chunk <raw> --x <hex> [--ctx <hex> --view <hex> --net mainnet|stagenet] \
         [--bob-dest <hex>] [--open-link <hex>] --monero <daemon-url>... \
         [--wallet-rpc <url> --wallet-password <pw> --sweep-dest <addr>] \
         [--reserve-address <addr> --reserve-message <hex> --reserve-proof <str> --reserve-amount <raw>] \
         --live"
    );
    eprintln!(
        "swapper --serve <127.0.0.1:port> [--token <pairing-token>] [--ws-origin <origin> ...] \
         --monero <daemon-url>... [--wallet-rpc <url> --wallet-password <pw>] \
         [--role maker|taker --listen|--connect <addr> --x <hex> --nano <url> ...] --live"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use transport::ws::WsWire;

    #[test]
    fn bridge_authenticates_then_answers_ping() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let ws = WsWire::accept(stream).unwrap();
            let xmr = swap_executor::DryRun;
            serve_bridge_client(ws, "sekret", &xmr, &[], None, None, None);
        });

        let client = WsWire::connect(&format!("ws://{addr}/ws")).unwrap();
        client.send(b"sekret".to_vec()).unwrap();
        client.send(br#"{"op":"ping"}"#.to_vec()).unwrap();
        let resp = String::from_utf8_lossy(&client.recv().unwrap()).into_owned();
        assert!(resp.contains("\"pong\":true"), "resp: {resp}");
        // Close our side so the server's recv returns and its thread can exit.
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn bridge_reports_no_session_when_unconfigured() {
        // With no session the helper honestly reports configured:false, so the
        // page shows "connect your wallet" rather than any fabricated swap.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let ws = WsWire::accept(stream).unwrap();
            let xmr = swap_executor::DryRun;
            serve_bridge_client(ws, "sekret", &xmr, &[], None, None, None);
        });
        let client = WsWire::connect(&format!("ws://{addr}/ws")).unwrap();
        client.send(b"sekret".to_vec()).unwrap();
        client.send(br#"{"op":"session_info"}"#.to_vec()).unwrap();
        let resp = String::from_utf8_lossy(&client.recv().unwrap()).into_owned();
        assert!(resp.contains("\"configured\":false"), "resp: {resp}");
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn bridge_reports_checkpoint_and_refuses_blind_resume() {
        // A saved Alice checkpoint is reported present with its role; resume
        // without session key material declines cleanly (never guesses keys).
        let path = std::env::temp_dir()
            .join(format!("xnoxmr-bridge-cp-{}.json", std::process::id()));
        let cp = swap_executor::AliceCheckpoint {
            joint: swap_executor::JointXmr {
                context: [1; 32],
                spend_pubs: vec![[2; 32], [3; 32]],
                spend_pub: [4; 32],
                view_key: [5; 32],
                address: "5JointAddr".into(),
            },
            presig: signing::adaptor::PreSignature {
                r_adapted: [6; 32],
                s_hat: [7; 32],
                adaptor_point: [8; 32],
            },
            claim_hash: [9; 32],
            chunk: 42,
        };
        cp.save(&path).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let path_t = path.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let ws = WsWire::accept(stream).unwrap();
            let xmr = swap_executor::DryRun;
            serve_bridge_client(ws, "sekret", &xmr, &[], None, None, Some(&path_t));
        });

        let client = WsWire::connect(&format!("ws://{addr}/ws")).unwrap();
        client.send(b"sekret".to_vec()).unwrap();
        client.send(br#"{"op":"checkpoint_status"}"#.to_vec()).unwrap();
        let resp = String::from_utf8_lossy(&client.recv().unwrap()).into_owned();
        assert!(resp.contains("\"present\":true"), "resp: {resp}");
        assert!(resp.contains("\"role\":\"taker\""), "resp: {resp}");

        client.send(br#"{"op":"resume"}"#.to_vec()).unwrap();
        let resp = String::from_utf8_lossy(&client.recv().unwrap()).into_owned();
        assert!(resp.contains("no session configured"), "resp: {resp}");
        assert!(path.exists(), "a refused resume never deletes the checkpoint");

        drop(client);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bridge_rejects_wrong_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let ws = WsWire::accept(stream).unwrap();
            let xmr = swap_executor::DryRun;
            serve_bridge_client(ws, "sekret", &xmr, &[], None, None, None);
        });

        let client = WsWire::connect(&format!("ws://{addr}/ws")).unwrap();
        client.send(b"wrong".to_vec()).unwrap();
        // Server should close after a bad token: recv returns Closed.
        assert!(client.recv().is_err());
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn bridge_start_without_session_errors_cleanly() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let ws = WsWire::accept(stream).unwrap();
            let xmr = swap_executor::DryRun;
            serve_bridge_client(ws, "sekret", &xmr, &[], None, None, None);
        });

        let client = WsWire::connect(&format!("ws://{addr}/ws")).unwrap();
        client.send(b"sekret".to_vec()).unwrap();
        client.send(br#"{"op":"start"}"#.to_vec()).unwrap();
        let resp = String::from_utf8_lossy(&client.recv().unwrap()).into_owned();
        assert!(resp.contains("no session configured"), "resp: {resp}");
        drop(client);
        server.join().unwrap();
    }
}
