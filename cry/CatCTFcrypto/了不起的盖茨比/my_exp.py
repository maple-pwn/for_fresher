#最后得到的flag记得包上CatCTF
import base64 
from Crypto.Cipher import AES 
from Crypto.Util.strxor import strxor as xor 
from Crypto.Util.number import * 
import Crypto.Util.strxor as xo 
import libnum, codecs, numpy as np

#进行MTP攻击所需要的函数
def isChr(x):
    if ord('a') <= x and x <= ord('z'): return True
    if ord('A') <= x and x <= ord('Z'): return True
    return False

def infer(index, pos):
    if msg[index, pos] != 0:
        return
    msg[index, pos] = ord(' ')
    for x in range(len(c)):
        if x != index:
            msg[x][pos] = xo.strxor(c[x], c[index])[pos] ^ ord(' ')

def know(index, pos, ch):
    msg[index, pos] = ord(ch)
    for x in range(len(c)):
        if x != index:
            msg[x][pos] = xo.strxor(c[x], c[index])[pos] ^ ord(ch)

def getSpace():
    for index, x in enumerate(c):
        res = [xo.strxor(x, y) for y in c if x!=y]
        f = lambda pos: len(list(filter(isChr, [s[pos] for s in res])))
        cnt = [f(pos) for pos in range(len(x))]
        for pos in range(len(x)):
            dat.append((f(pos), index, pos))

#将key和c的值进行base64解码
key = b'+0zkhmid1PFjVdxSP09zSw=='
c = b'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'
key = base64.b64decode(key)
c = base64.b64decode(c)

#将题目中的加密结果转为攻击模板中的格式
cipher = AES.new(key,mode=AES.MODE_ECB)
t = []
for i in range(0,len(c),16):
    if i == 0:
        t.append(cipher.decrypt(c[i:i+16]))
    else:
        t.append(xor(cipher.decrypt(c[i:i+16]),c[i-16:i]))
tmp = []
tmp.append(t[0])
for i in range(1,len(t)):
    tt = t[i]
    for j in range(0,i):
        tt = xor(tt,t[j])
    tmp.append(tt)

#MTP攻击
c = tmp
dat = []
msg = np.zeros([len(c), len(c[0])], dtype=int)
getSpace()
dat = sorted(dat)[::-1]
for w, index, pos in dat:
    infer(index, pos)

#打印结果
print(''.join([''.join([chr(c) for c in x]) for x in msg]))
