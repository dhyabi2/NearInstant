// Node side of the Rust<->JS MailboxWire interop proof. Uses web/mailbox.js
// (the exact browser client) against a file-backed dumb relay shared with the
// Rust `mailbox_file` example. Run via deploy/mailbox_interop_test.sh.
//   node mailbox_interop.cjs enc <shared_hex> <initiator 0|1> <dir> <plaintext>
//   node mailbox_interop.cjs dec <shared_hex> <initiator 0|1> <dir>
const fs = require("fs");
const path = require("path");
const M = require("./mailbox.js");

function FileRelay(dir) {
  return {
    async post(m, s, b) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, `${m}_${s}.bin`), Buffer.from(b));
      return true;
    },
    async fetch(m, s) {
      const p = path.join(dir, `${m}_${s}.bin`);
      if (!fs.existsSync(p)) return null;
      return new Uint8Array(fs.readFileSync(p));
    },
  };
}

(async () => {
  const [, , mode, sharedHex, init, dir, text] = process.argv;
  const shared = Uint8Array.from(Buffer.from(sharedHex, "hex"));
  const { send, recv, key } = await M.derive(shared, init === "1");
  const wire = new M.MailboxWire([FileRelay(dir)], send, recv, key);
  wire.pollMs = 10; wire.timeoutMs = 3000;
  if (mode === "enc") {
    await wire.send(new TextEncoder().encode(text));
    process.stderr.write("node sent\n");
  } else {
    const m = await wire.recv();
    process.stdout.write(Buffer.from(m).toString("utf8"));
  }
})().catch(e => { process.stderr.write("ERR " + e + "\n"); process.exit(1); });
