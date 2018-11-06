#!/usr/bin/python3

#Sbox2 = [0x1, 0x0, 0x5, 0x3, 0xe, 0x2, 0xf, 0x7, 0xd, 0xa, 0x9, 0xb, 0xc, 0x8, 0x4, 0x6]

Sbox1 = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]

p = [0, 10, 5, 15, 14, 4, 11, 1, 9, 3, 12, 6, 7, 13, 2, 8]
invP = [0, 7, 14, 9, 5, 2, 11, 12, 15, 8, 1, 6, 10, 13, 4, 3]

#M = [0,1,1,1, 1,0,1,1, 1,1,0,1, 1,1,1,0]

a0  = [0,0,0,1, 0,1,0,1, 1,0,1,1, 0,0,1,1]
a1  = [0,1,1,1, 1,0,0,0, 1,1,0,0, 0,0,0,0]
a2  = [1,0,1,0, 0,1,0,0, 0,0,1,1, 0,1,0,1]
a3  = [0,1,1,0, 0,0,1,0, 0,0,0,1, 0,0,1,1]
a4  = [0,0,0,1, 0,0,0,0, 0,1,0,0, 1,1,1,1]
a5  = [1,1,0,1, 0,0,0,1, 0,1,1,1, 0,0,0,0]
a6  = [0,0,0,0, 0,0,1,0, 0,1,1,0, 0,1,1,0]
a7  = [0,0,0,0, 1,0,1,1, 1,1,0,0, 1,1,0,0]
a8  = [1,0,0,1, 0,1,0,0, 1,0,0,0, 0,0,0,1]
a9  = [0,1,0,0, 0,0,0,0, 1,0,1,1, 1,0,0,0]
a10 = [0,1,1,1, 0,0,0,1, 1,0,0,1, 0,1,1,1]
a11 = [0,0,1,0, 0,0,1,0, 1,0,0,0, 1,1,1,0]
a12 = [0,1,0,1, 0,0,0,1, 0,0,1,1, 0,0,0,0]
a13 = [1,1,1,1, 1,0,0,0, 1,1,0,0, 1,0,1,0]
a14 = [1,1,0,1, 1,1,1,1, 1,0,0,1, 0,0,0,0]
alpha = [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14]

resultat0 = [0x3, 0xc, 0x9, 0xc, 0xc, 0xe, 0xd, 0xa, 0x2, 0xb, 0xb, 0xd, 0x4, 0x4, 0x9, 0xa]
resultat1 = [0x6, 0x6, 0xb, 0xc, 0xd, 0xc, 0x6, 0x2, 0x7, 0x0, 0xd, 0x9, 0x0, 0x1, 0xc, 0xd]


def subCell(mot):
	return Sbox1[mot]


def subCells(matrice):
	res = [0 for i in range(16)]
	for j in range(16):
		res[j] = subCell(matrice[j])
	return res


def shuffleCells(matrice):
	res = [0 for i in range(16)]
	for i in range(16):
		res[i] = matrice[p[i]]
	return res


def invShuffleCells(matrice):
	res = [0 for i in range(16)]
	for i in range(16):
		res[i] = matrice[invP[i]]
	return res


def mixColumn(matrice):
	res = [0 for i in range(16)]
	for i in range(4):
		res[0+4*i] = matrice[1+4*i] ^ matrice[2+4*i] ^ matrice[3+4*i]
		res[1+4*i] = matrice[0+4*i] ^ matrice[2+4*i] ^ matrice[3+4*i]
		res[2+4*i] = matrice[0+4*i] ^ matrice[1+4*i] ^ matrice[3+4*i]
		res[3+4*i] = matrice[0+4*i] ^ matrice[1+4*i] ^ matrice[2+4*i]
	return res


def addKey(matrice, key):
	res = [0 for i in range(16)]
	for i in range(16):
		res[i] = matrice[i] ^ key[i]
	return res


def midori(m, k):
	wk = addKey(k[0:16], k[16:32])
	rk = [0 for i in range(16)]

	res = addKey(m, wk)
	for i in range(15):
		rk = addKey(k[0+16*(i%2) : 16+16*(i%2)], alpha[i])
		res = subCells(res)
		res = shuffleCells(res)
		res = mixColumn(res)
		res = addKey(res, rk)
	res = subCells(res)
	res = addKey(res, wk)
	return res


def antiMidori(m, k):
	wk = addKey(k[0:16], k[16:32])
	rk = [0 for i in range(16)]

	res = addKey(m, wk)
	for i in range(14, -1, -1):
		rk = addKey(k[0+16*(i%2) : 16+16*(i%2)], alpha[i])
		res = subCells(res)
		res = mixColumn(res)
		res = invShuffleCells(res)
		tmpRK = invShuffleCells(mixColumn(rk))
		res = addKey(res, tmpRK)
	res = subCells(res)
	res = addKey(res, wk)
	return res


if __name__ == '__main__':
	msg0 = [0x0 for i in range(16)]
	key0 = [0x0 for i in range(32)]
	res0 = midori(msg0, key0)
	print(res0)
	print(resultat0)
	print(antiMidori(res0, key0))
	print('\n')

	msg1 = [0x4, 0x2, 0xc, 0x2,
			0x0, 0xf, 0xd, 0x3,
			0xb, 0x5, 0x8, 0x6,
			0x8, 0x7, 0x9, 0xe]

	key1 = [0x6, 0x8, 0x7, 0xd,
			0xe, 0xd, 0x3, 0xb,
			0x3, 0xc, 0x8, 0x5,
			0xb, 0x3, 0xf, 0x3,

			0x5, 0xb, 0x1, 0x0,
			0x0, 0x9, 0x8, 0x6,
			0x3, 0xe, 0x2, 0xa,
			0x8, 0xc, 0xb, 0xf]
	res1 = midori(msg1,	key1)
	print(res1)
	print(resultat1)
	print(antiMidori(res1, key1))
