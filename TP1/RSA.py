#!/bin/env python3

import random

def is_prime(x):
    return ( test(2, x) and test(3, x) and test(5, x) and test(7, x) )

def test(nb, x):
    return (exporap(nb, x-1, x) % x) == 1



def prime_generator():
    primes = [i for i in range(0, 50) if is_prime(i)]
    res_p = random.choice(primes)
    res_q = random.choice(primes)
    return res_p, res_q

def Generation():

    p,q = prime_generator()
    # Compute
    n = p * q
    phi = (p - 1) * (q - 1)

    # Select an arbitrary integer e with 1 < e < phi and gcd(e,phi) == 1
    e = int(random.randint(1,phi))
    pgcd = pgcd(e,phi)
    while pgcd != 1:
        e = int(random.randint(1,phi))
        pgcd = pgcd(e,phi)

    # e,n is public key

    # Compute the integer d statisfying 1 < d < phi and e*d == 1 % phi
    d = igcd(phi,e)
    if d<0:
        inv_modulo(d,n)

    # Return n e d
    print("Public Key: " + str(e))
    print("Private Key: " + str(d))
    print("n = " + str(n))
    return n,e,d

def exporap(x,n,mod):
    #retourne la valeur de x puissance n
    if n == 1:
        return x % mod
    if n/2 == 0:
        tmp = exporap((x*x) % mod ,n/2,mod)
        return (tmp * tmp) % mod
    else :
        tmp = x* exporap((x*x) % mod ,(n-1)/2,mod)
        return (((tmp * tmp) % mod)* tmp) %mod
def pgcd(a,b):
    if b==0:
        return a
    else:
        r=a%b
        return pgcd(b,r)

def igcd(a,b):
    # Initialisation
    d,u,v,d1,u1,v1=a,1,0,b,0,1
    # Calcul
    while d1!=0:
        q=d//d1
        d,u,v,d1,u1,v1=d1,u1,v1,d-q*d1,u-q*u1,v-q*v1
    #return (d,u,v)
    return u

def bezout(e, phi):
    ''' Calcule (u, v, p) tels que e*u + phi*v = p et p = pgcd(a, b) '''
    if e == 0 and phi == 0: return (0, 0, 0)
    if phi == 0: return (e/abs(e), 0, abs(e))
    (u, v, p) = bezout(phi, e%phi)
    return (v, (u - v*(e/phi)), p)

def inv_modulo(x, m):
    ''' Calcule y dans [[0, m-1]] tel que x*y % abs(m) = 1 '''
    (u, _, p) = bezout(x, m)
    if p == 1: return u%abs(m)
    else: raise Exception("%s et %s ne sont pas premiers entre eux" % (x, m))

# INPUT: RSA public key e, n, message m
def Encryption(e, n, m):
    c = [pow(ord(char),e,n) for char in m]
    print(''.join(map(lambda x: str(x), c)))
    return c

    # INPUT: RSA private key d, n, ciphertext c
def Decryption(d, n, c):
    m =  [chr(pow(char, d, n)) for char in c]
    print(''.join(m))
    return ''.join(m)

def main():
    msg = input("Message a chiffrer: ")
    e,n = Generation()
    c = Encryption(e, msg)
    print("msg =", msg)
    print("c =", c)

# main()
print(is_prime(7))
