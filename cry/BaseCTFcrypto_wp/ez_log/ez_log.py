from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b

pad = lambda x: x + b'\x00' * (16 - len(x) % 16)

def decrypt(KEY, enc):
    cipher = AES.new(KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(enc)
    return decrypted

enc = 33416570913716503492297352041317858420349510954381249751537743898024527101872454706181188441210166165803904185550746

x = 38806815

enc_bytes = l2b(enc)
key_bytes = pad(l2b(x)) 

flag = decrypt(key_bytes, enc_bytes)
print(flag)