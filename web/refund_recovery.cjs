const W = require("../swap-core/wasm-bridge/pkg-node/wasm_bridge.js");
const X = require("../swap-core/wasm-monero/pkg-node/wasm_monero.js");
const crypto = require("crypto");
const hx = b => Buffer.from(b).toString("hex");
let pass=0, fail=0;
const ok=(c,m)=>{c?(pass++,console.log("  PASS "+m)):(fail++,console.log("  FAIL "+m));};
const L = 2n**252n + 27742317777372353535851937790883648493n;
const mScalar = () => { let v=0n; const b=crypto.randomBytes(32);
  for(let i=31;i>=0;i--) v=(v<<8n)|BigInt(b[i]); v%=L;
  const o=new Uint8Array(32); for(let i=0;i<32;i++){o[i]=Number(v&0xffn);v>>=8n;} return o; };

console.log("\n1. Joint Nano account via 2-of-2 FROST DKG");
const dA=new W.BrowserDkg(1,2), dB=new W.BrowserDkg(2,1);
const a1=dA.round1_out(), b1=dB.round1_out();
dA.set_peer_round1(b1); dB.set_peer_round1(a1);
const a2=dA.round2_out(), b2=dB.round2_out();
const acctA=dA.set_peer_round2(b2), acctB=dB.set_peer_round2(a2);
ok(hx(acctA)===hx(acctB), "both sides derive the same joint account");
const sA=new W.BrowserSigner(dA.key_package(),dA.public_key_package(),1,2);
const sB=new W.BrowserSigner(dB.key_package(),dB.public_key_package(),2,1);

console.log("\n2. Monero shares and the joint address");
const A_xmr=mScalar(), B_xmr=mScalar();
const A_pub=X.xmr_spend_pub(A_xmr), B_pub=X.xmr_spend_pub(B_xmr);
const ctx=crypto.createHash("sha256").update("xnoxmr-2p-ctx-v1:offer").digest();
const vA=crypto.randomBytes(32), vB=crypto.randomBytes(32);
const joint=JSON.parse(X.xmr_joint_info(ctx,A_pub,B_pub,vA,vB,"mainnet"));
ok(!!joint.address, "joint Monero address derived: "+joint.address.slice(0,16)+"…");

console.log("\n3. REFUND as an adaptor pre-signature bound to TA = A's Monero pubkey");
const refundHash=crypto.randomBytes(32);
const cA=sA.presign_commit(refundHash,A_pub), cB=sB.presign_commit(refundHash,A_pub);
sA.set_peer_commit(cB); sB.set_peer_commit(cA);
const shA=sA.presign_share(), shB=sB.presign_share();
sA.set_peer_share(shB); sB.set_peer_share(shA);
const preA=sA.aggregate_presig(), preB=sB.aggregate_presig();
ok(hx(preA)===hx(preB), "both sides compute the identical refund pre-signature");
ok(W.presig_verify(preA,acctA,refundHash), "refund pre-signature verifies");
ok(!W.nano_check(acctA,refundHash,preA.slice(0,64)), "pre-signature alone is NOT a valid Nano signature");

console.log("\n4. A takes the refund by completing it with A_xmr");
const refundSig=W.presig_complete(preA,A_xmr);
ok(W.nano_check(acctA,refundHash,refundSig), "completed refund IS a valid Nano signature (broadcastable)");

console.log("\n5. B extracts A's Monero share from the on-chain refund signature");
const extracted=W.presig_extract(preB,refundSig);
ok(hx(extracted)===hx(A_xmr), "extracted secret equals A_xmr  <-- the whole point");

console.log("\n6. B reconstructs the joint Monero key and can sweep its lock back");
const fromB=X.xmr_joint_secret(ctx,B_xmr,extracted);
const fromA=X.xmr_joint_secret(ctx,A_xmr,B_xmr);
ok(hx(fromB)===hx(fromA), "B's reconstruction (B_xmr,A_xmr) == A's (A_xmr,B_xmr)");
ok(hx(X.xmr_spend_pub(fromB))!==hx(A_pub), "joint secret is not either party's own key");

console.log("\n7. Regression: the CLAIM path still works, bound to T = B's pubkey");
const claimHash=crypto.randomBytes(32);
const c2A=sA.presign_commit(claimHash,B_pub), c2B=sB.presign_commit(claimHash,B_pub);
sA.set_peer_commit(c2B); sB.set_peer_commit(c2A);
const s2A=sA.presign_share(), s2B=sB.presign_share();
sA.set_peer_share(s2B); sB.set_peer_share(s2A);
const pre2=sA.aggregate_presig();
const claimSig=W.presig_complete(pre2,B_xmr);
ok(W.nano_check(acctA,claimHash,claimSig), "claim completes with B_xmr and verifies");
ok(hx(W.presig_extract(pre2,claimSig))===hx(B_xmr), "A extracts x=B_xmr from the claim");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
