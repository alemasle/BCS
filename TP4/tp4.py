#!/usr/bin/env python3

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





def string_to_bytes(m='a'):
    li = ""
    for i in m:
        tmp = bin(ord(i))[2:]
        while len(tmp) < 8:
            tmp = '0' + tmp
        li += tmp
    return li

message = input("Message:\n")
msg = string_to_bytes(message)
print(msg)
decoupe_blocks(msg, 10)
