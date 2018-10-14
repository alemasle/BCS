#!/bin/env python3
import random

A0 = [0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1]
A1 = [0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0]
A2 = [1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1]
A3 = [0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1]
A4 = [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1]
A5 = [1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0]
A6 = [0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0]
A7 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0]
A8 = [1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1]
A9 = [0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0]
A10 = [0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1]
A11 = [0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0]
A12 = [0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0]
A13 = [1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0]
A14 = [1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0]

A = [A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14]

def aes_input(message):
    key = gen_key()
    res = midori64(message, key)
    return res

def gen_key():
    return random.getrandbits(128)

def midori64(msg, k):
    K = [k & 0xFFFFFFFFFFFFFFFF, k >>64]
    WK = K[0]^K[1]
    a = A
    s = msg ^ WK
    for i in range(15):
        s = SubCell(s)
        s = ShuffleCell(s)
        s = MixColumns(s)
        s ^= K[i%2] ^ a[i]
    s = SubCell(s)
    return s^WK

def SubCell(s):
    sbox = [0xc,0xa,0xd,0x3,0xe,0xb,0xf,0x7,0x8,0x9,0x1,0x5,0x0,0x2,0x4,0x6]
    res = 0
    for i in range(16):
        res |= sbox[(s >> 4*i)& 0xf] << 4*i
    return res

def ShuffleCell(s):
    p = [0,10,5,15,14,4,11,1,9,3,12,6,7,13,2,8]
    res = 0
    for i in range(16):
        res |= ((s >> 4*p[i])& 0xf) << 4*i
    return res

def MixColumns(s):
    res = 0
    for i in range(4):#t est une colonne
        t = (s>>16*i)& 0xFFFF
        u = ((t >> 4)^(t>>8)^(t>>12))& 0xF
        u |= ((t^(t>>8)^(t>>12)) & 0xf) << 4
        u |= ((t^(t>>8)^(t>>12)) & 0xF) << 8
        u |= ((t^(t>>8)^(t>>12)) & 0xF) << 12
        res |= u << 16*i
    return res

def main():
    msg = input("Entrez 64 bits ( int ):\n")
    aes_input(int(msg))
    # from Midori_imported import MidoriEncrypt
    # from Midori_imported import MidoriDecrypt
    #
    # plaintext = input("Message 32 octets max:\n") # 32 chars
    #
    # plainHex = "0x" + plaintext.encode("utf-8").hex() #Transforme la string d'entree en string hexadecimal
    # key = "0x687ded3b3c85b3f35b1009863e2a8cbf" #Cle prise dans l'autre programme (Aleatoire ?)
    # round = 20 # Plante au dessus de 20 round
    #
    # c = MidoriEncrypt(plainHex, key, round)
    # p = MidoriDecrypt(c, key, round)
    #
    # print("\nPlainHexa:", plainHex)
    # print("key:", key)
    # print("cipher:", c)
    # print("Resultat decryption:", bytes.fromhex(p[2:]).decode('utf-8'))


main()
