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
'miner_public_key':pub_key_str,
'transactions': []}

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
    #print('Received potential block:',data)
    if is_valid_block(data):
        print('Block valid')
        if data['id']>last_id:
            last_id = data['id'] # TODO: discover if this is a part of a genuine blockchain
            last_block = data
    else:
        print('block invalid')

def get_block_reward():
    return 100

def is_valid_transaction(xact):
    for i in ['time','from','to','amount','transaction_fee','block_id','transaction_id','message','signature']:
        if i not in xact:
            print(f'transaction missing required field {i}')
            return False
    if xact['from'] is None:
        return True # this may be a valid block reward
    try:
        print('decoding sign bytes')
        sign = bytes.fromhex(xact['signature'])
        print('importing key')
        pub_key = ECC.import_key(xact['from'])
        hashes = []
        print('hashing transaction')
        for field in ['time','from','to','amount','transaction_fee','block_id','transaction_id','message']:
            hashes.extend(fieldhash(xact[field]))
        hashes = b''.join(hashes)
        h = SHA256.new(hashes)
        print('verifying transaction')
        verifier = DSS.new(key, 'fips-186-3')
        verifier.verify(h, sign)
    except:
        print('Checking transaction failed.')
        traceback.print_exc()
        return False
    return True


def amount_if_block_reward(xact):
    if xact['from'] is None:
        return xact['amount']
    return 0

def is_valid_block(block):
    for i in ['id','time','nonce','prev_hash','version','threshold', 'miner_public_key', 'message', 'transactions']:
        if i not in block:
            print(f'required field {i} missing from block')
            return False
    block_rewards = 0
    for i in block['transactions']:
        if not is_valid_transaction(i):
            print(f'{i} is not a valid transaction')
            return False
        block_rewards += amount_if_block_reward(i)
        if block_rewards > get_block_reward():
            print('block reward too large')
            return False
        if block_rewards < get_block_reward():
            print('block reward too small')
            return False
    return blockhash(block)<int(block['threshold'], 16)

def stringhash(string):
    val = bytes(string, 'utf-8')
    return hashlib.sha256(val).digest()

def inthash(integer):
    return stringhash(str(integer))

# from http://rightfootin.blogspot.com/2006/09/more-on-python-flatten.html
def flatten(l):
  out = []
  for item in l:
    if isinstance(item, (list, tuple)):
      out.extend(flatten(item))
    else:
      out.append(item)
  return out


def fieldhash(obj):
    if obj is None:
        return [stringhash('')]
    elif isinstance(obj, str):
        return [stringhash(obj)]
    elif isinstance(obj, int):
        return [inthash(obj)]
    elif isinstance(obj, dict):
        return flatten([fieldhash(i) for i in obj.values()])
    elif isinstance(obj, list):
        return flatten([fieldhash(i) for i in obj])
    else:
        raise TypeError(f'Unknown type of object: {obj} (type {type(obj)})')

        

def blockhash(block):
    hashes = []
    for i in block.values():
        hashes.extend(fieldhash(i))
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
                'message':'Mined by danya02',
                'transactions':[
                    {'from': None,
                    'to':pub_key_str,
                    'amount': 100,
                    'transaction_fee':0,
                    'block_id': last_id+1,
                    'transaction_id': '',
                    'message': 'block reward',
                    'signature': None,
                    'time': 0
                    }
                ]
            }
        valid = True
        while blockhash(block)>threshold:
            block['time']=int(time.time()*1000)
            block['transactions'][0]['time'] = block['time']
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


class Blockchain:
    class JSONDict:
        def __init__(self):
            self.objs = {}
        def __getitem__(self, item):
            try:
                if item not in self.blocks:
                    with open(f'danya02_blockchain/{item}.json') as o:
                        self.objs.update({item: json.load(o)})
                return self.objs[item]
            except:
                return IndexError(traceback.format_exc())

        def __setitem__(self, item, value):
            self.objs[item] = value
            try:
                os.mkdir('danya02_blockchain')
            except FileExistsError:
                pass
            with open(f'danya02_blockchain/{item}.json', 'w') as o:
                o.write(json.dumps(value))
        def __delitem__(self, item):
            del self.objs[item]
            os.unlink(f'danya02_blockchain/{item}.json')
        def __len__(self):
            try:
                os.mkdir('danya02_blockchain')
            except FileExistsError:
                pass
            return len(os.listdir('danya02_blockchain/'))

    def __init__(self, client):
        self.client = client
        self.blocks = JSONDict()
        self.active_chat_sessions = []

    def parse_message(self, message):
        try:
            message = json.loads(message)
            if message['action']=='length_announce':
                if message['length']>len(self.blocks):
                    self.start_new_chat_session(message)
                elif message['length']<len(self.blocks):
                      self.announce_my_length()
        except:
            for i in self.active_chat_sessions:
                try:
                    i.parse_message(message)
                    return None
                except:
                    pass
    def announce_my_length(self):
        client.publish('blockexchange',payload=json.dumps({"action": "length_announce", "public key": pub_key_str, "length": len(self.blocks)}))

    def start_new_chat_session(self, message):
        try:
            self.active_chat_sessions.append(ChatSession(message['public_key']))
        except:
            print('Error while starting chat session:')
            traceback.print_exc()



client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect('localhost',1883)
client.loop_start()
start_mining()


