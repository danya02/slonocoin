#!/usr/bin/python3
import hashlib
import time
import traceback
import json
import paho.mqtt.client as mqtt

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

try:
    print('Loading keys...')
    priv_key = ECC.import_key(open('privkey.pem').read())
    pub_key_str = open('pubkey.pem').read()
except FileNotFoundError:
    print('Keys not found, generating...')
    key = ECC.generate(curve='p521')
    print('Generation complete.')
    priv_key = key.export_key(format='PEM')
    file_out = open("privkey.pem", "w")
    file_out.write(priv_key)
    file_out.close()
    priv_key = ECC.import_key(priv_key)

    pub_key_str = key.public_key().export_key(format='PEM')
    file_out = open("pubkey.pem", "w")
    file_out.write(pub_key_str)
    file_out.close()

threshold = int('f'*64,16)//300000
block = {"id":0,
"time":0,
"nonce":0,
"prev_hash":"",
"version":"v0",
"threshold":'0',
'message':'Mined by danya02',
'miner_public_key':pub_key_str}

last_block = block
last_id=0

def on_connect(client, userdata, flags, rc):
    print('Connected to server')
    client.subscribe('blocks')

def on_message(client, userdata, msg):
    global last_id
    global last_block
    try:
        data = json.loads(str(msg.payload, 'utf-8'))
    except:
        traceback.print_exc()
        return None
    if is_valid_block(data):
        if data['id']>last_id:
            last_id = data['id']
            last_block = data

def is_valid_block(block):
    for i in ['id','time','nonce','prev_hash','version','threshold', 'miner_public_key', 'message']:
        if i not in block:
            return False
    return blockhash(block)<int(block['threshold'], 16)

def stringhash(string):
    val = bytes(string, 'utf-8')
    return hashlib.sha256(val).digest()

def inthash(integer):
    return stringhash(str(integer))

def blockhash(block):
    hashes = []
    for i in block.values():
        if isinstance(i, str):
            hashes.append(stringhash(i))
        elif isinstance(i,int):
            hashes.append(inthash(i))
        else:
            raise TypeError(f'Unknown type of object: {i} (type {type(i)})')
    hashes.sort()
    return int(hashlib.sha256(b''.join(hashes)).hexdigest(),16)

def start_mining():
    global last_id
    global last_block
    last_id = 0
    my_mined_blocks = 0
    while 1:
        block = {"id":last_id+1,
                "time":0,
                "nonce":0,
                "prev_hash":hex(blockhash(last_block))[2:].rjust(64,'0'),
                "version":"v0",
                "threshold":hex(threshold)[2:].rjust(64,'0'),
                'miner_public_key':pub_key_str,
                'message':'Mined by danya02'}
        valid = True
        while blockhash(block)>threshold:
            block['time']=int(time.time()*1000)
            block['nonce']+=1
            if last_id>=block['id']:
                valid = False
                break
        if valid:
            my_mined_blocks +=1
            print('Block',block['id'],'mined by me!')
            client.publish('blocks',payload=json.dumps(block))
            last_id = block['id']
            last_block = block
        else:
            print('Block',last_id,'mined: ',last_block['message'])
        print('My stats:',my_mined_blocks,'/',last_id,'=',my_mined_blocks/last_id)


client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect('localhost',1883)
client.loop_start()
start_mining()


if False:
    st = time.time()
    c=0
    try:
        print(hex(blockhash(block)), hex(threshold), sep='\n')
        while blockhash(block)>threshold:
            block['time']=int(time.time())
            block['nonce']+=1
            c+=1
        print(block)
    except:
        traceback.print_exc()
        et=time.time()
        print('start time:',st,',end time:',et,',diff:',et-st)
        print('hashes:',c)
        print('h/s:',c/(et-st))
