#!/bin/env python3

import hashlib


r = 0
c = 0
lr = 576

RC = [
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
  0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
  0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
  0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
  0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
  0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

def change_to_be_bin(m='a'):
    x = 0
    for c in m:
        x <<= 8
        x |= ord(c)
    return bin(x)[2:]

def keccak(lr=576, c=1024):
    for i in range(24):
        r = r ^ m0

m = change_to_be_bin()

def padding(m=m,lr=576):
    mess = []
    if len(m)<lr:
        if len(m)>lr-1: #on crée un deuxieme bloc 0---01
            mess.append(m|1)
            mess.append(0|1)
        else:
            mess.append(m|1)
            for i in range((lr-2)-len(m)):
                mess[mess.count()-1] = mess[mess.count()-1]|0
            mess[mess.count()-1] = mess[mess.count()-1]|1
    else:
        mess.append(m[0:lr])
        mess.append(padding(m[lr:],lr))
    return mess

def sha3Hash(string):
    s = hashlib.sha3_256()
    s.update(data)
    dig = s.hexdigest()
    return dig;


def main():
    data = input("Message to hash sha3-256:\n").encode()
    sha3Hash(data)



main()
