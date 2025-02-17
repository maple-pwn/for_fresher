from secret import flag
import random

assert flag.startswith('hsctf{')

N = 128
m1 = flag[4:-1]
key = 'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890{}_#&'

def encrypt(m, a, b):
    c = ''
    kt = random.getrandbits(len(m))
    for mt in m:
        tmp = key.find(mt) 
        k = kt
        for _ in range(len(m)):
            tmp = tmp * a if k % 2 == 0 else tmp + b
            k = k // 2
        c += key[tmp % len(key)]
    return c

print(encrypt(m1, random.getrandbits(N), random.getrandbits(N)))
# WhcuU0o4Vc0VUasJc08W04uJ0qd2IJpVJ02V04p
