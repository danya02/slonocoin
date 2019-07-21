#!/usr/bin/python3
import hashlib
import time
import traceback
import json
import paho.mqtt.client as mqtt


threshold = int('f'*64,16)//300000
block = {"id":0,
"time":0,
"nonce":0,
"prev_hash":"",
"version":"v0",
"threshold":'0',
'debug_mined_by':'danya02'}

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
    for i in ['id','time','nonce','prev_hash','version','threshold']:
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
            raise TypeError('Unknown type of object')
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
                "prev_hash":hex(blockhash(last_block))[2:],
                "version":"v0",
                "threshold":hex(threshold)[2:],
                'debug_mined_by':'danya02'}
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
            print('Block',last_id,'mined by',last_block['debug_mined_by'])
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
