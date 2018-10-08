#!/bin/env python3
r = 0
c = 0
lr = 576

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
