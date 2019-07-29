#!/usr/bin/python3
import hashlib
import time
import traceback
import json
import paho.mqtt.client as mqtt
import threading
import os

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

class Miner:
    def __init__(self):
        self.load_keys()
        threshold = int('f'*64,16)//300000
        self.block = {"id":0,
        "time":0,
        "nonce":0,
        "prev_hash":"",
        "version":"v0",
        "threshold":'0',
        'message':'Mined by danya02',
        'miner_public_key':self.pub_key_str,
        'transactions': []}

        client = mqtt.Client()

        self.blockchain = Blockchain(client)
        client.on_connect = self.on_connect
        client.on_message = self.on_message
        
        client.connect('localhost',1883)
        client.loop_start()

        self.client = client

        self.start_mining()


    def get_block_reward(self):
        return 100
    
    @staticmethod
    def stringhash(string):
        val = bytes(string, 'utf-8')
        return hashlib.sha256(val).digest()

    @staticmethod
    def inthash(integer):
        return Miner.stringhash(str(integer))

    # from http://rightfootin.blogspot.com/2006/09/more-on-python-flatten.html
    @staticmethod
    def flatten(l):
        out = []
        for item in l:
            if isinstance(item, (list, tuple)):
                out.extend(Miner.flatten(item))
            else:
                out.append(item)
        return out

    @staticmethod
    def fieldhash(obj):
        if obj is None:
            return [Miner.stringhash('')]
        elif isinstance(obj, str):
            return [Miner.stringhash(obj)]
        elif isinstance(obj, int):
            return [Miner.inthash(obj)]
        elif isinstance(obj, dict):
            return Miner.flatten([Miner.fieldhash(i) for i in obj.values()])
        elif isinstance(obj, list):
            return Miner.flatten([Miner.fieldhash(i) for i in obj])
        else:
            raise TypeError(f'Unknown type of object: {obj} (type {type(obj)})')

        
    @staticmethod
    def blockhash(block):
        hashes = []
        for i in block.values():
            hashes.extend(Miner.fieldhash(i))
        hashes.sort()
        return int(hashlib.sha256(b''.join(hashes)).hexdigest(),16)

    @staticmethod
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
                hashes.extend(Miner.fieldhash(xact[field]))
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

    @staticmethod
    def amount_if_block_reward(xact):
        if xact['from'] is None:
            return xact['amount']
        return 0

    @staticmethod
    def is_valid_block(block):
        for i in ['id','time','nonce','prev_hash','version','threshold', 'miner_public_key', 'message', 'transactions']:
            if i not in block:
                print(f'required field {i} missing from block')
                return False
        block_rewards = 0
        for i in block['transactions']:
            if not Miner.is_valid_transaction(i):
                print(f'{i} is not a valid transaction')
                return False
            block_rewards += amount_if_block_reward(i)
            if block_rewards > get_block_reward():
                print('block reward too large')
                return False
            if block_rewards < get_block_reward():
                print('block reward too small')
                return False
        if self.blockhash(block)<int(block['threshold'], 16):
            return True
        else:
            print('Block hash is too high!')
            return False

    def start_mining(self):
        threading.Thread(target = self.mining_thread).start()

    @staticmethod
    def is_parent_block(old, new):
        return new['id'] == old['id'] + 1 and new['prev_hash'] == hex(Miner.blockhash(old))[2:].rjust(32,'0')

    def mining_thread(self):
        block = self.block
        my_mined_blocks = 0
        while 1:
            block = {"id":self.blockchain.last_block['id']+1,
                    "time":0,
                    "nonce":0,
                    "prev_hash":hex(self.blockhash(self.blockchain.last_block))[2:].rjust(64,'0'),
                    "version":"v0",
                    "threshold":hex(self.blockchain.threshold)[2:].rjust(64,'0'),
                    'miner_public_key':self.pub_key_str,
                    'message':'Mined by danya02',
                    'transactions':[
                        {'from': None,
                        'to':self.pub_key_str,
                        'amount': 100,
                        'transaction_fee':0,
                        'block_id': self.blockchain.last_block['id']+1,
                        'transaction_id': '',
                        'message': 'block reward',
                        'signature': None,
                        'time': 0
                        }
                    ]
                }
            valid = True
            while self.blockhash(block)>self.blockchain.threshold:
                block['time']=int(time.time()*1000)
                block['transactions'][0]['time'] = block['time']
                block['nonce']+=1
                if block['id'] < self.blockchain.last_block['id']:
                    block = self.blockchain.blocks[block['id']]
                    valid = False
                    break
            if valid:
                my_mined_blocks +=1
                print('Block',block['id'],'mined by me!')
                self.blockchain.publish(block)
            else:
                print('Block',block['id'],'mined: ',self.blockchain.last_block['message'])
            print('My stats:',my_mined_blocks,'/',block['id'],'=',my_mined_blocks/block['id'])

    def load_keys(self):
        try:
            print('Loading keys...')
            self.priv_key = ECC.import_key(open('privkey.pem').read())
            self.pub_key_str = open('pubkey.pem').read()
        except FileNotFoundError:
            print('Keys not found, generating...')
            key = ECC.generate(curve='p521')
            print('Generation complete.')
            priv_key = key.export_key(format='PEM')
            file_out = open("privkey.pem", "w")
            file_out.write(priv_key)
            file_out.close()
            self.priv_key = ECC.import_key(priv_key)

            self.pub_key_str = key.public_key().export_key(format='PEM')
            file_out = open("pubkey.pem", "w")
            file_out.write(self.pub_key_str)
            file_out.close()


    def on_connect(self, client, userdata, flags, rc):
        print('Connected to server')
        client.subscribe('blocks')

    def on_message(self, client, userdata, msg):
        self.blockchain.parse_message(msg.topic, msg.payload)


def cache_for_duration(dur):
    def cache_function(func):
        def cache_inner(obj):
            try:
                if time.time()-cache_inner.last_call>dur:
                    raise AttributeError
            except AttributeError:
                cache_inner.last_value = func()
                cache_inner.last_call = time.time()
            return cache_inner.last_value
        return cache_inner
    return cache_function

class Blockchain:
    class JSONDict:
        def __init__(self):
            self.objs = {}
        def __getitem__(self, item):
            try:
                if item not in self.objs or self.objs[item] in [True, False]:
                    with open(f'danya02_blockchain/{item}.json') as o:
                        self.objs.update({item: json.load(o)})
                return self.objs[item]
            except:
                raise IndexError(traceback.format_exc())

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

        def __contains__(self, obj):
            if obj in self.objs and isinstance(self.objs[obj], bool):
                return self.objs[obj]
            elif obj in self.objs:
                return True
            try:
                self.objs[obj] = f'{obj}.json' in os.listdir('danya02_blockchain/')
            except FileNotFoundError:
                os.mkdir('danya02_blockchain/')
                self.objs[obj] = False
            return self.objs[obj]

    def __init__(self, client):
        self.client = client
        self.blocks = Blockchain.JSONDict()
        self.active_chat_sessions = []
        self.last_block = {'id':1, 'message':'not really'}

    @property
    @cache_for_duration(60)
    def threshold():
        return int('ff'*30,16)

    def publish(self, block):
        self.blocks[block['id']] = block
        self.client.publish('blocks',payload=json.dumps(block))
        self.last_block = block

    def parse_message(self, topic, message):
        try:
            message = json.loads(message)
        except ValueError: # message is not JSON so maybe one of the chat sessions can decrypt it
            for i in self.active_chat_sessions:
                try:
                    i.parse_message(message)
                    return None
                except:
                    pass
            return None
        if topic=='blockexchange': # message is length announcement
            try:
                if message['action']=='length_announce':
                    if message['length']>len(self.blocks):
                        self.start_new_chat_session(message)
                    elif message['length']<len(self.blocks):
                          self.announce_my_length()
            except [KeyError, TypeError]:
                print('Invalid length announce recvd')
                
        elif topic=='blocks':
            if Miner.is_valid_block(message): # message is block announcement
                print('heard valid block')
                if message['id'] > self.last_block['id']:
                    print('that is higher id than I know of')
                    if message['id'] - self.last_block['id'] > 1: # jump in block id numbers
                        print('By a significant amount')
                        self.get_blocks_starting_from(message['id'])
                    elif Miner.is_parent_block(self.last_block, message):
                        self.blocks[message['id']] = message
                        self.last_block = message

    
    def announce_my_length(self):
        client.publish('blockexchange',payload=json.dumps({"action": "length_announce", "public key": pub_key_str, "length": len(self.blocks)}))

    def start_new_chat_session(self, message):
        try:
            self.active_chat_sessions.append(ChatSession(message['public_key']))
        except:
            print('Error while starting chat session:')
            traceback.print_exc()

class ChatSession:
    def __init__(self, public_key):
        raise NotImplemented

if __name__ == '__main__':
    m=Miner()
