#!/usr/bin/env python3
import random
import argparse
from sys import argv
from Midori64 import midori
from SHA3 import sha3Hash

def decoupe_blocks(data, size):
    data_size = len(data)
    nb_block = data_size//size
    bits_restants = data_size%size

    list_block = []

    for i in range(0, data_size, size):
        list_block.append(data[i: i+size])

    while len(list_block[-1]) < size:
        list_block[-1] = list_block[-1] + '0'

    return list_block

def array_to_hex(li):
    res = ""
    for c in li:
        res += hex(c)[2:]
    return res

def int_to_hex(i):
    h = hex(i)[2:]
    while len(h) < 8:
        h = '0' + h
    return h

def CTR(nonce, blocks, key):
    ctr = 0
    nonce_counter = string_to_hex(nonce + int_to_hex(ctr))
    list_ret = []
    for b in blocks:
        ret = midori(nonce_counter, key)
        res = array_to_hex(ret)
        list_ret.append(hex(int(res, 16) ^ int(b, 16))[2:])
        ctr += 1
        nonce_counter = string_to_hex(nonce + int_to_hex(ctr))

    return list_ret

def string_to_hex(m):
    res = []
    for c in m:
        tmp = '0x' + c
        res.append(int(tmp, 16))
    return res

def hash_mdp(key):
    hash = sha3Hash(key) # Return hash taille 64
    tmp = int(hash[:32], 16)
    tmp2 = int(hash[32:], 16)
    tmp3 = hex(tmp ^ tmp2)[2:] # Return hash taille 32

    while len(tmp3) < 32:   # Complete par un 0 si la forme hexadecimal du xor rend 31 chars
        tmp3 = '0' + tmp3

    return tmp3


def generate_from_mdp(hmdp):
    tmp = hmdp[:16] + hex(1)
    tmp2 = hmdp[16:] + hex(2)
    ke = sha3Hash(tmp.encode())
    # print("len key:", len(ke))
    ke = hash_mdp(ke.encode())   # Return key taille 32 (hash)
    # print("len key:", len(ke))
    nonce = sha3Hash(tmp2.encode())[:24] # Nonce taille 24 hexa pour atteindre 32 char hexa avec le counter
    return ke, nonce


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("message", help="Le message a chiffrer")
    parser.add_argument("key", help="La clé de chiffrement (hexa)")
    args = parser.parse_args()

    size_block = 16 #16 en char hexa soit 8 octets --> 64 bits

    msg = args.message.encode().hex()
    hmdp = hash_mdp(args.key.encode())
    ke, nonce = generate_from_mdp(hmdp)
    ke = string_to_hex(ke) # Transforme en tableau d'hexadecimal

    li = decoupe_blocks(msg, size_block)

    res = CTR(nonce, li, ke) # Chiffrement
    print("chiffre:", "".join(res))

    # Derivation de cles/vecteurs d'initialisation a partir d'un mot de passe
    # MAC()    EMAC ou CMAC par exemple (HMAC?)
    # Chiffre authentifie base sur Encrypt-then-MAC

    cl = CTR(nonce, res, ke) # Dechiffrement

    final = ""
    for b in cl:
        final += b

    print("dechiffre:", bytes.fromhex(final).decode())

if __name__ == '__main__':
    main()


#
