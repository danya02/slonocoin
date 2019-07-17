
extern crate serde_derive;

extern crate serde;
extern crate serde_json;

extern crate crypto;

use serde_derive::{Deserialize, Serialize};


use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use crypto::digest::Digest;
use crypto::sha2::Sha256;


#[derive(Serialize, Deserialize, Debug, Clone)]
struct Block {
    id: u128,
    time: u64,
    nonce: i128,
    prev_hash: String,
    version: String,
    threshold: String,
}

fn hexcompare(a:&str, b:&str) -> Ordering {
    match a.len().cmp(&b.len()) {
        Ordering::Greater => {return Ordering::Greater;},
        Ordering::Less => {return Ordering::Less;},
        Ordering::Equal => {
            for (x,y) in a.chars().zip(b.chars()){
                let ord = x.cmp(&y);
                if ord != Ordering::Equal{ return ord; }

            }
        }
    }
    return Ordering::Equal;
}

fn stringhash(s:&str) -> [u8;32] {
    let mut hasher = Sha256::new();
    hasher.input_str(s);
    let mut hash:[u8;32] = [0;32];
    hasher.result(&mut hash);
    hash
}

fn get_constant_hashes(b:Block) -> Vec<[u8;32]> {
    let mut hashvec = Vec::new();
    hashvec.push(stringhash(&b.prev_hash));
    hashvec.push(stringhash(&b.version));
    hashvec.push(stringhash(&b.threshold));

    hashvec.push(stringhash(&b.id.to_string()));

    hashvec
}

fn get_unix_time() -> u64{

    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs()
}


fn hash_full(mut prepared:Vec<[u8;32]>, time:u64, nonce:i128) -> [u8;32]{
    prepared.push(stringhash(&time.to_string()));
    prepared.push(stringhash(&nonce.to_string()));
    prepared.sort_by(|a, b| a.cmp(b));
    let mut hasher = Sha256::new();
    for i in prepared {
        hasher.input(&i)
    }
    let mut hash:[u8;32] = [0;32];
    hasher.result(&mut hash);
    hash
}
fn mine_block(mut b:Block) {
    let prepared = get_constant_hashes(b.clone());
    while true{
        b.nonce+=1;
        let val = hash_full(prepared.clone(), get_unix_time(), b.nonce);
        print!("{}: ",b.nonce);
        for i in val.iter() {print!("{};",i);}println!(".");
    }
}
fn main() {
    let blockstr =  r#"{"id":122,
"time":0,
"nonce":0,
"prev_hash":"deadbeefdeadbeef",
"version":"v1",
"threshold":"beefdead"}
"#;
    let b: Block = serde_json::from_str(blockstr).unwrap();
    println!("{:?}", b);
    println!("{:?}", hexcompare("9","a"));
    mine_block(b);
}
