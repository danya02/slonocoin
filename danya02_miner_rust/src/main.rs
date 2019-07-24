
extern crate serde_derive;

extern crate serde;
extern crate serde_json;

extern crate crypto;

extern crate mosquitto_client as mosq;

use serde_derive::{Deserialize, Serialize};


use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use mosq::{Mosquitto, MosqMessage};
extern crate hex;

use hex::FromHex;

extern crate itertools;
use itertools::Itertools;


use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Block {
    id: u128,
    time: u64,
    nonce: i128,
    prev_hash: String,
    version: String,
    threshold: String,
    debug_mined_by: String,
}

impl Block {
    fn new() -> Block {
        Block {id: 1, time: 0, nonce: 0, prev_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(), version: "v0".to_string(), threshold: "".to_string(), debug_mined_by: "danya02".to_string()}
    }
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

fn u8compare(a:[u8;32], b:[u8;32]) -> Ordering {
    for (x,y) in a.iter().zip(b.iter()) {
        let ord = x.cmp(&y);
        if ord != Ordering::Equal {return ord;}
    }
    return Ordering::Equal;
}

fn hex2u8(a:&str) -> Result<[u8;32], hex::FromHexError> {
    <[u8; 32]>::from_hex(a)
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

    hashvec.push(stringhash(&b.debug_mined_by));
    hashvec.push(stringhash(&b.id.to_string()));

    hashvec
}

fn get_unix_time() -> u64{

    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs()*1000 + (since_the_epoch.subsec_millis() as u64)
}


fn hash_from_prep(mut prepared:Vec<[u8;32]>, time:u64, nonce:i128) -> [u8;32]{
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

fn full_hash_vec(blk:Block) -> (Vec<String>,Block) {
    let mut prepared = get_constant_hashes(blk.clone());
    prepared.push(stringhash(&blk.time.to_string()));
    prepared.push(stringhash(&blk.nonce.to_string()));
    prepared.sort_by(|a, b| a.cmp(b));
    let mut outp = Vec::new();
    for i in prepared {outp.push(u8tohex(i));}
    (outp, blk)
}

#[derive(Debug)]
enum BlockInvalidErr {
    HashTooHigh(String, String, Vec<String>),
    IDTooLow,
    PrevBlockHashMismatch,
    PrevBlockHashUndecodable
}

fn get_full_hash(b:Block) -> ([u8;32],Block) {
    let prep = get_constant_hashes(b.clone());
    (hash_from_prep(prep.clone(), b.time, b.nonce),b)
}

fn block_validate(b:Block, prevb: Block, threshold:[u8;32]) -> Result<(Block, Block), (BlockInvalidErr, Block)> {
    if b.id<=prevb.id {return Err((BlockInvalidErr::IDTooLow, prevb));}
    let (hash, block) = get_full_hash(b.clone());
    if u8compare(hash, threshold) == Ordering::Less {
        let (prevhash,prevblock) = get_full_hash(prevb);
        let prevhashval = hex2u8(&block.prev_hash);
        let targetprevhash;
        match prevhashval {
            Ok(x) => {targetprevhash = x;},
            Error => {
                return Result::Err((BlockInvalidErr::PrevBlockHashUndecodable,prevblock));
            }
        };
        if u8compare(prevhash, targetprevhash) == Ordering::Equal {
            Ok((block, prevblock))
        } else {return Err((BlockInvalidErr::PrevBlockHashMismatch, prevblock));}
    } else {
        let (hashlist, blk) = full_hash_vec(b);
        return Err((BlockInvalidErr::HashTooHigh(u8tohex(hash), u8tohex(threshold), hashlist), prevb));
    }
}


fn on_message(senders: Vec<i32>, msg: MosqMessage){
    //let blockres: Result<Block> = serde_json::from_str(blockstr);

}


fn get_threshold() -> [u8;32] {
    hex2u8("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()
}

fn u8tohex(a:[u8;32]) -> String {
    let alphabet = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
    let mut s = String::new();
    for i in a.iter() {
        s.push(alphabet[(i/16) as usize]);
        s.push(alphabet[(i%16) as usize]);
    }
    s
}

fn mining_thread(id:u8, recv: Receiver<Block>, send: Sender<Block>) {
    let mut block_to_mine = Block::new();
    let mut prev_block = Block::new();
    prev_block.id=0;
    block_to_mine.id = 0;
    block_to_mine.threshold = u8tohex(get_threshold());
    let mut prepared = get_constant_hashes(block_to_mine.clone());
    let mut threshold = get_threshold();
    println!("Thread {} started",id);
    loop {
        let newblockres = recv.try_recv();
        match newblockres {Ok(block) => {
            println!("{}: Received new block: {:?}",id, block);
            let newblock = block;
            let block_valid = block_validate(newblock, prev_block, get_threshold());
            match block_valid
            {
                Ok((block, prevblock)) => {
                    println!("{}: Received block is valid",id);
                    prev_block = block; // TODO: add more validation: check history is continuous to last block we heard of (or to origin block if our history was wrong)
                    block_to_mine.id = prev_block.id + 1;
                    let (prevhash, blk) = get_full_hash(block_to_mine);
                    block_to_mine = blk;
                    block_to_mine.prev_hash = u8tohex(prevhash);
                    block_to_mine.threshold = u8tohex(get_threshold());
                    block_to_mine.nonce=0;
                    prepared = get_constant_hashes(block_to_mine.clone());
                    threshold = get_threshold();

                
                },
                    Err((error,prevblock)) => {println!("{}: received block is invalid: {:?}",id,error); prev_block = prevblock;}
            }

                    
            }, Err(_) => ()
        }
        
    
        block_to_mine.nonce+=1;
        block_to_mine.time = get_unix_time();
        //let (hash, mined_block) = get_full_hash(block_to_mine);
        //block_to_mine = mined_block;
        let hash = hash_from_prep(prepared.clone(), block_to_mine.time, block_to_mine.nonce);
        let valid = u8compare(hash, threshold) == Ordering::Less;
        if valid {
            println!("{}: Found valid block id {}, block is {:?}",id,block_to_mine.id, block_to_mine);
            send.send(block_to_mine);
            block_to_mine = Block::new();
            block_to_mine.prev_hash = u8tohex(hash);
            block_to_mine.threshold = u8tohex(get_threshold());
            block_to_mine.nonce=0;
            prepared = get_constant_hashes(block_to_mine.clone());
            threshold = get_threshold();
        }
    }
}


fn distribute_block(b:Block, s:Vec<Sender<Block>>) -> Vec<Sender<Block>> {
    for send in &s{
        send.send(b.clone());
    }
    s
}


fn main() {
    let blockstr =  r#"{"id":122,
"time":0,
"nonce":0,
"prev_hash":"deadbeefdeadbeef",
"version":"v1",
"threshold":"beefdead",
"debug_mined_by":"danya02"}
"#;
    
    let m = Mosquitto::new("conn");
    println!("Connecting to server");
    m.connect("localhost",1883); // TODO: more robust connection
    m.subscribe("blocks",1);
    println!("Setting up threads");
    

    let threadcount = 4;
    let mut miners = Vec::new();
    let mut recvs = Vec::new();
    let mut sends = Vec::new();
    for id in 0..threadcount {
        println!("Setting up thread {}",id);
        let (send_into_thread, recv_into_thread): (Sender<Block>, Receiver<Block>) = mpsc::channel();
        let (send_out_thread, recv_out_thread): (Sender<Block>, Receiver<Block>) = mpsc::channel();
        let child = thread::spawn(move ||{mining_thread(id, recv_into_thread, send_out_thread);});
        miners.push(child);
        sends.push(send_into_thread);
        recvs.push(recv_out_thread);
    }

    let mut mc = m.callbacks(Vec::<i32>::new());
    mc.on_message(|data, msg| {on_message(data.to_vec(), msg);});
    
    loop {
        m.do_loop(10);
        for recv in &recvs {
            let newblockres = recv.try_recv();
            match newblockres {
                Ok(block) => {
                    sends = distribute_block(block, sends);

                },
                Err(_) => ()
            }
        }
    }




    
/*    let mut b: Block = serde_json::from_str(blockstr).unwrap();
    println!("{:?}", hexcompare("9","a"));
    println("{:?", hex!(hash_full(get_constant_hashes(b.clone()), 0, 0)));
    let start = SystemTime::now();
    b = mine_block(b);
    let end = SystemTime::now();
    let time = (end.duration_since(start).unwrap().as_nanos() as f64) /1_000_000_000.0;
    println!("{:?}", b);
    println!("Hashes: {}, time: {}, h/s: {}",b.nonce, time, (b.nonce as f64)/time);
*/



}
