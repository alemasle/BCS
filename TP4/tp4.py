#!/usr/bin/env python3
import random
from sys import argv
import argparse

def decoupe_blocks(data, size):
    data_size = len(data)
    nb_block = data_size//size
    bits_restants = data_size%size

    list_block = []

    for i in range(0, data_size, size):
        list_block.append(data[i: i+size])

    while len(list_block[-1]) < size:
        list_block[-1] = '0' + list_block[-1]

    return list_block

def CBC(iv, blocks, key, size):

    list_chiffre = []
    previous = iv
    for b in blocks:
        tmp_block = int(b, 2)
        tmp_prev = int(previous, 2)
        xored = tmp_block ^ tmp_prev
        chiffrement = bin(chiffrage(xored, int(key,2))[2:]

        while len(chiffrement) < size: # add '0' to make 8 bits long in string
            chiffrement = '0' + chiffrement

        list_chiffre.append(chiffrement)
        previous = list_chiffre[-1]

    print(list_chiffre)
    return list_chiffre

def chiffrage(msg, key):
    print(msg)
    print(key)
    return msg ^ key


def string_to_bytes(m='a'):
    li = ""
    for i in m:
        tmp = bin(ord(i))[2:]
        while len(tmp) < 8:
            tmp = '0' + tmp
        li += tmp
    return li

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("message", help="Le message a chiffrer")
    parser.add_argument("clef", help="La clé de chiffrement (Message)")
    args = parser.parse_args()


    size_block = 10
    # message = input("Message:\n")
    # clef = input("Clé:\n")
    msg = string_to_bytes(args.message)
    key = string_to_bytes(args.clef)
    li = decoupe_blocks(msg, size_block)
    iv = bin(random.getrandbits(size_block))[2:]

    print("message:", args.message, "\nclef:", args.clef)
    # print("message:", msg, "\niv:", iv, "\nkey:", key)
    # print("block decoupes:", li)

    CBC(iv, li, key, size_block)


main()

#
