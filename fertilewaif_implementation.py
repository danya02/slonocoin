import json
from hashlib import sha256
import random
import time
import math
import paho.mqtt.client as mqtt

threshold = int('f'*64,16)//300000

class Miner():
    def __init__(self, client):
        self.client = client
        self.last_id = -1
        self.last_block = {
            "id":0,
            "time":0,
            "nonce":0,
            "prev_hash":"",
            "version":"v0",
            "threshold":'0',
            'debug_mined_by':'fertilewaif'
        }
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

    blockFields = ['id', 'time', 'nonce', 'prev_hash', 'version', 'threshold']

    def is_valid_block(self, blockJson):
        for field in self.blockFields:
            if field not in blockJson:
                return False
        return self.hash_block(blockJson) < int(blockJson['threshold'], 16)

    def on_connect(self, userdata, flags, rc):
        self.client.subscribe('blocks')
    
    def on_message(self, userdata, msg):
        try:
            block = json.loads(str(msg.payload, 'utf-8'))
        except:
            print("Error occured on message")
            return
        if self.is_valid_block(block):
            if block['id'] > self.last_id:
                self.last_id = block['id']
                self.last_block = block

    def connect(self, ip, port):
        self.client.connect(ip, port)
        self.client.loop_start()

    def mine(self):
        self.last_id = 0
        total = 0
        while True:
            block = {
                "id":self.last_id+1,
                "time":0,
                "nonce":0,
                "prev_hash":self.hash_block(self.last_block),
                "version":"v0",
                "threshold":hex(threshold)[2:],
                'debug_mined_by':'fertilewaif'
            }
            valid = True
            while int(self.hash_block(block), 16) > threshold:
                block['time'] = time.time()
                block['nonce'] += 1
                if self.last_id >= block['id']:
                    valid = False
                    break
            if valid:
                print("Block", self.last_id + 1, "mined")
                total += 1
                print(total, "out of",  self.last_id + 1, "mined by me")
                self.client.publish('blocks', payload=json.dumps(block))
                self.last_id = block['id']
                self.last_block = block
            else:
                print("Block", block['id'], "is invalid")


    def generate_new_block(self, jsonObject, nonce):
        jsonObject["nonce"] = nonce
        return jsonObject

    def hash_block(self, jsonStr):
        hashes = []
        jsonObject = None
        if isinstance(jsonStr, str):
            jsonObject = json.loads(jsonStr)
        else:
            jsonObject = jsonStr
        for key in jsonObject:
            #print(key, jsonObject[key])
            hashes.append(sha256(bytes(str(jsonObject[key]), 'utf-8')).digest())
        hashes.sort()
        all_hashes_sorted = b''.join([i for i in hashes])
        #print(hashes)
        return sha256(all_hashes_sorted).hexdigest()


if __name__ == "__main__":
    miner = Miner(mqtt.Client())
    miner.connect("192.168.43.254", 1883)
    miner.mine()