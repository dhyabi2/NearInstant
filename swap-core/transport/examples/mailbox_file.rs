//! Rust side of the Rust<->JS MailboxWire interop proof (see
//! deploy/mailbox_interop_test.sh). A file-backed dumb relay so a Node process
//! running web/mailbox.js exchanges an authenticated message with the native
//! MailboxWire — demonstrating a browser can join a swap whose counterparty
//! runs the native code.
//!
//!   mailbox_file enc <shared_hex> <initiator 0|1> <dir> <plaintext>
//!   mailbox_file dec <shared_hex> <initiator 0|1> <dir>   (prints plaintext)

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use transport::mailbox::{derive, MailboxWire, Relay};
use transport::Wire;

struct FileRelay(PathBuf);
impl Relay for FileRelay {
    fn post(&self, m: &str, s: u64, b: &[u8]) -> Result<(), String> {
        fs::create_dir_all(&self.0).map_err(|e| e.to_string())?;
        fs::write(self.0.join(format!("{m}_{s}.bin")), b).map_err(|e| e.to_string())
    }
    fn fetch(&self, m: &str, s: u64) -> Result<Option<Vec<u8>>, String> {
        Ok(fs::read(self.0.join(format!("{m}_{s}.bin"))).ok())
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mode = a[1].as_str();
    let shared: [u8; 32] = hex::decode(&a[2]).unwrap().try_into().unwrap();
    let init = a[3] == "1";
    let dir = PathBuf::from(&a[4]);
    let (send, recv, key) = derive(&shared, init);
    let wire = MailboxWire::new(vec![Box::new(FileRelay(dir))], send, recv, key)
        .with_polling(Duration::from_millis(10), Duration::from_secs(3));
    match mode {
        "enc" => {
            wire.send(a[5].as_bytes().to_vec()).expect("send");
            eprintln!("rust sent");
        }
        "dec" => {
            let m = wire.recv().expect("recv");
            print!("{}", String::from_utf8_lossy(&m));
        }
        _ => panic!("mode must be enc|dec"),
    }
}
