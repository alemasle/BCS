#!/usr/bin/env python3
import random
import argparse
from sys import argv
from Midori64 import midori
import hashlib

def sha3Hash(data):
    s = hashlib.sha3_256()
    s.update(data)
    dig = s.hexdigest()
    return dig;

def decoupe_blocks(data, size, mode="enc"):
    data_size = len(data)
    nb_block = data_size//size
    bits_restants = data_size%size

    list_block = []
    for i in range(0, data_size, size):
        list_block.append(data[i: i+size])

    if mode == "enc":
        if len(list_block[-1]) == size: # Cas bloc plein --> Ajout d'un bloc complet de padding 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1
            tmp = ['0']*16
            tmp[0] = '1'
            tmp[-1] = '1'
            list_block.append("".join(tmp))

        elif len(list_block[-1]) == size -1: # Cas bloc avec un emplacement libre, on met un '1' et
                                             # on remplis de '0' un nouveau bloc que l'on termine par '1'
            list_block[-1] += '1'
            tmp = ['0']*16
            tmp[-1] = '1'
            list_block.append("".join(tmp))

        else:                                # Cas d'un bloc non rempli, on pad avec 1 0 0 .. 0 1
            tmp_li = list(list_block[-1])
            tmp_len = len(tmp_li)

            to_pad = size - tmp_len

            tmp_li.append('1')
            tmp_li += ['0']*(to_pad -2)
            tmp_li.append('1')

            list_block[-1] = "".join(tmp_li)

    # while len(list_block[-1]) < size:
    #     list_block[-1] = list_block[-1] + '0'

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
        fin = hex(int(res, 16) ^ int(b, 16))[2:]
        while len(fin) < 16:   # Complete par un 0 si la forme hexadecimal du xor rend 16 chars
            fin = '0' + fin
        list_ret.append(fin)
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
    tmp3 = hmdp + hex(3)
    ke = sha3Hash(tmp.encode())
    ke = hash_mdp(ke.encode())   # Return key taille 32 (hash)
    nonce = sha3Hash(tmp2.encode())[:24] # Nonce taille 24 hexa pour atteindre 32 char hexa avec le counter
    mackey = sha3Hash(tmp3.encode())
    return ke, nonce, mackey

def HMAC(mackey, msg): # Generer un hash de taille 8 octets
    tmp = msg + mackey
    h = hash_mdp(tmp.encode())
    h = hex( int(h[:16],16) ^ int(h[16:],16) )[2:]
    while len(h) < 16:   # Complete par un 0 si la forme hexadecimal du xor rend 15 chars ou moins
        h = '0' + h
    return h


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group2 = parser.add_mutually_exclusive_group(required=True)
    group3 = parser.add_mutually_exclusive_group(required=True)

    # Cypher mode
    group.add_argument("--enc", help="Mode Chiffrement", action="store_true")
    group.add_argument("--dec", help="Mode Dechiffrement", action="store_true")

    # Input mode
    group2.add_argument("-m","--message", help="Le message a chiffrer/dechiffrer")
    group2.add_argument("--message-file", help="Le fichier a chiffrer/dechiffrer")

    # Input password mode
    group3.add_argument("-p","--password", help="Le mot de passe de chiffrement")
    group3.add_argument("--password-file", help="Le fichier contenant le mot de passe de chiffrement")

    parser.add_argument("-o","--output", help="Le fichier de sortie (sortie standard par défaut)", default="stdout")
    args = parser.parse_args()

    # Recupere le message sous forme de string
    msg = ""
    if args.message is not None:
        if args.enc:
            msg = args.message.encode().hex()
        elif args.dec:
            msg = args.message
            modulo = len(msg)%16
            if msg[-1] == "\n":
                msg = msg[:-1]
            if modulo != 0:
                print("This message can not be uncypher. (Wrong format)")
                exit(0)

    elif args.message_file is not None:
        if args.enc:
            with open(args.message_file, encoding="utf-8") as file:
                msg = file.read().encode().hex() # On transforme en hexadecimal le message du fichier

        elif args.dec:
            with open(args.message_file, encoding="utf-8") as file:
                msg = file.read() # On recupere l'hexadecimal du fichier
                if msg[-1] == "\n":
                    msg = msg[:-1]
                modulo = len(msg)%16
                if modulo != 0:
                    print(msg, len(msg))
                    print("This message can not be uncypher. (Wrong format)")
                    exit(0)

        if msg == "":
            print("The file", args.message_file, "is empty")
            exit(0)

    else:
        print("You must give a message or a file in argument")
        exit(0)

    # Recupere le mot de passe sous forme de string
    mdp = ""
    if args.password is not None:
        mdp = args.password

    elif args.password_file is not None:
        with open(args.password_file) as file_pass:
            mdp = file_pass.read() # On recupere le contenu du fichier avec le mot de passe
        if mdp == "":
            print("The file", args.password_file, "is empty")
            exit(0)

    else:
        print("You must give a password or a file un argument")
        exit(0)

    hmdp = hash_mdp(mdp.encode()) # Creer un hash du mot de passe
    key, nonce, mackey = generate_from_mdp(hmdp) # Derivation de cles/vecteur d'initialisation (nonce) a partir du mot de passe
    key = string_to_hex(key) # Transforme la clef en tableau d'hexadecimal

    if args.dec: # verification Signature MAC
        tmp_mac = msg[-16:] # Recupere le MAC du chiffre
        tmp_cypher = msg[:-16] # Recupere le message du chiffre
        resultat = HMAC(mackey, tmp_cypher)
        if resultat != tmp_mac:
            print("Signature ou mot de passe invalide!")
            exit(0)
        else:
            msg = msg[:-16] # Separation du mac et du message


    size_block = 16 #16 en char hexa soit 8 octets --> 64 bits
    mode = "dec" if args.dec else "enc"
    li = decoupe_blocks(msg, size_block, mode) # Decoupe le message en n bloc de 8 octets

    res = CTR(nonce, li, key) # Chiffrement/Dechiffrement de tous les blocs avec le mode CTR

    final = ""
    if args.enc:
        final = "".join(res)

    elif args.dec:
        final = "".join(res)

    if final[-1] == '1': # Suppresion du padding
        final = final[:-1]
        while final[-1] == '0':
            final = final[:-1]

        if final[-1] == '1':
            final = final[:-1]

        final = bytes.fromhex(final).decode()



    if mode == 'enc': # Encrypt-then-MAC
        mac = HMAC(mackey, final) # Signature MAC du message
        final = final + mac # Concatenation du message chiffre et son MAC sur 8 octets supplementaires

    if args.output == "stdout":
        print("Resultat:", final)
    else:
        with open(args.output, "w") as file:
            file.write(final)
        print("-->", args.output)


if __name__ == '__main__':
    main()