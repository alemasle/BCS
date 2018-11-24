#!/usr/bin/env python3
import random
import argparse
import hashlib
import binascii
import multiprocessing
from sys import argv
from Midori64 import midori

def sha3Hash(data):
    s = hashlib.sha3_256()
    s.update(data)
    dig = s.hexdigest()
    return dig;


def cutting(data, data_size, size=16, child=None):
    list_block = [data[i:i+size] for i in range(0, data_size, size) ]

    if child is None:
        return list_block
    else:
        child.send(list_block)


def decoupe_blocks(data, size, mode="enc"):
    data_size = len(data)
    nb_block = data_size//size
    bits_restants = data_size%size

    list_block = []

    if nb_block >= 4:
        parent1, child1 = multiprocessing.Pipe()
        parent2, child2 = multiprocessing.Pipe()
        parent3, child3 = multiprocessing.Pipe()
        parent4, child4 = multiprocessing.Pipe()

        """
        Exemple nb_block = 10

        first_bordure = data[0:2]
        second_bordure = data[2:4]
        third_bordure = data[4:6]
        forth_bordure = data[6:8]

        if nb_block % 4 > 0:
            fifth_bordure = data[8:]
        """

        index = (nb_block // 4)*size

        first_bordure = data[0 : index]
        second_bordure = data[index : 2*index]
        third_bordure = data[2*index : 3*index]
        forth_bordure = data[3*index : 4*index]
        fifth_bordure =  ""

        if nb_block % 4 > 0:
            fifth_bordure = data[4*index : ]


        p = multiprocessing.Process(target=cutting, args=(first_bordure, len(first_bordure), size, child1))
        p2 = multiprocessing.Process(target=cutting, args=(second_bordure, len(second_bordure), size, child2))
        p3 = multiprocessing.Process(target=cutting, args=(third_bordure, len(third_bordure), size, child3))
        p4 = multiprocessing.Process(target=cutting, args=(forth_bordure, len(forth_bordure), size, child4))

        p.start()
        p2.start()
        p3.start()
        p4.start()

        p1_recv = parent1.recv()
        p2_recv = parent2.recv()
        p3_recv = parent3.recv()
        p4_recv = parent4.recv()
        p5_recv = []

        if fifth_bordure != "":
            parent5, child5 = multiprocessing.Pipe()
            p5 = multiprocessing.Process(target=cutting, args=(fifth_bordure, len(fifth_bordure), size, child5))
            p5.start()
            p5_recv = parent5.recv()
            p5.join()
            parent5.close(); child5.close()

        list_block = p1_recv + p2_recv + p3_recv + p4_recv + p5_recv

        p.join()
        p2.join()
        p3.join()
        p4.join()

        parent1.close(); child1.close()
        parent2.close(); child2.close()
        parent3.close(); child3.close()
        parent4.close(); child4.close()

    else:
        list_block = cutting(data, data_size, size)

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
    length_blocks = len(blocks) - 1
    for b in blocks:
        ret = midori(nonce_counter, key)
        res = array_to_hex(ret)
        fin = hex(int(res, 16) ^ int(b, 16))[2:]
        while len(fin) < 16:   # Complete par un 0 si la forme hexadecimal du xor rend moins de 16 chars
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
    tmp = hmdp[:16] + hex(1)[2:]
    tmp2 = hmdp[16:] + hex(2)[2:]
    tmp3 = hmdp + hex(3)[2:]
    ke = sha3Hash(tmp.encode()) # 64 hexa
    ke = hash_mdp(ke.encode())   # Return key taille 32 (hash)
    nonce = sha3Hash(tmp2.encode())[:24] # Nonce taille 24 hexa pour atteindre 32 char hexa avec le counter
    mackey = sha3Hash(tmp3.encode())
    return ke, nonce, mackey

def HMAC(mackey, msg): # Generer un hash de taille 8 octets
    tmp = msg + mackey
    h = hash_mdp(tmp.encode())
    h = hex( int(h[:16],16) ^ int(h[16:],16) )[2:]
    while len(h) < 16:   # Complete par un 0 si la forme hexadecimal du xor rend 16 chars ou moins
        h = '0' + h
    return h


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group2 = parser.add_mutually_exclusive_group(required=True)
    group3 = parser.add_mutually_exclusive_group(required=True)

    # Cypher mode
    group.add_argument("-e","--enc", help="Mode Chiffrement", action="store_true")
    group.add_argument("-d","--dec", help="Mode Dechiffrement", action="store_true")

    # Input mode
    group2.add_argument("-m","--message", help="Le message a chiffrer/dechiffrer")
    group2.add_argument("--message-file", help="Le fichier a chiffrer/dechiffrer")

    # Input password mode
    group3.add_argument("-p","--password", help="Le mot de passe de chiffrement/dechiffrement")
    group3.add_argument("--password-file", help="Le fichier contenant le mot de passe de chiffrement/dechiffrement")

    parser.add_argument("-o","--output", help="Le fichier de sortie (sortie standard par défaut)", default="stdout")
    args = parser.parse_args()

    # Recupere le message sous forme de string
    msg = ""
    binary = False
    if args.message is not None:
        if args.enc:
            msg = args.message.encode().hex()
        elif args.dec:
            msg = args.message
            if msg[-1] == "\n":
                msg = msg[:-1]
            modulo = len(msg)%16
            if modulo != 0:
                print("This message can not be uncypher. (Wrong format)")
                exit(0)

    elif args.message_file is not None:
        if args.enc:
            try:
                with open(args.message_file, "r") as file:
                    msg = file.read().encode().hex() # On transforme en hexadecimal le message du fichier
            except UnicodeDecodeError as e:
                with open(args.message_file, "rb") as file:
                    msg = file.read().hex()
                    binary = True

        elif args.dec:
            with open(args.message_file, "r") as file:
                msg = file.read() # On recupere l'hexadecimal du fichier
                if msg[-3:] == 'bin':
                    binary = True
                    msg = msg[:-3]

            if msg[-1] == "\n":
                msg = msg[:-1]
            modulo = len(msg)%16
            if modulo != 0:
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
        with open(args.password_file, 'r') as file_pass:
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
            else:
                print("Error padding")
                exit(0)


    if mode == 'enc': # Encrypt-then-MAC
        mac = HMAC(mackey, final) # Signature MAC du message
        final = final + mac # Concatenation du message chiffre et son MAC sur 8 octets supplementaires

    if args.output == "stdout":
        if not binary and args.dec:
            final = bytes.fromhex(final).decode()
        print(final)

    else:
        if binary and args.dec:
            with open(args.output, "wb") as file:
                final = binascii.unhexlify(final)
                file.write(final)
        else:
            with open(args.output, "w") as file:
                if binary and args.enc:
                    final = final + 'bin'   # On ajoute 'bin' a la fin pour que le dechiffrement sache le type de fichier

                elif not binary and args.dec:
                    final = bytes.fromhex(final).decode()

                file.write(final)

        print("-->", args.output)


if __name__ == '__main__':
    main()
