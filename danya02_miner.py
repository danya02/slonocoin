#!/usr/bin/python3
import hashlib
import time
import traceback

threshold = int('f'*64,16)//300000
block = {"id":122,
"time":0,
"nonce":0,
"prev_hash":"deadbeefdeadbeef",
"version":"v1",
"threshold":1000000}

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
