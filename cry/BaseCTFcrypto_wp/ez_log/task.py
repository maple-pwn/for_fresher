from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b, getPrime
from Crypto.Cipher import AES
from random import randint


flag = b"flag{test_flag}"

pad = lambda x: x+b'\x00'*(16-len(x)%16)

def encrypt(KEY):
    cipher= AES.new(KEY,AES.MODE_ECB)
    encrypted =cipher.encrypt(flag)
    return encrypted
def decrypt(KEY):
    cipher= AES.new(KEY,AES.MODE_ECB)
    decrypted =cipher.decrypt(enc)
    return decrypted

flag = pad(flag)
x = randint(10 ** 7, 10 ** 8)
y = randint(10 ** 7, 10 ** 8)
n = getPrime(28)
z = pow(y, x, n)

enc = encrypt(pad(l2b(x)))
print(f'enc = {b2l(enc)}')
print(f'y = {y}')
print(f'n = {n}')
print(f'z = {z}')

'''
enc = 33416570913716503492297352041317858420349510954381249751537743898024527101872454706181188441210166165803904185550746
y = 82941012
n = 228338567
z = 51306718
'''
