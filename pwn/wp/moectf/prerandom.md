# moectf 这是什么？random

by Maple

***伪随机数***

生成随机数的种子为一年中当前天数-1.所以直接照抄源码里生成随机数的逻辑

```python
from pwn import *
from ctypes import *
from time import localtime
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
#p = process('./pwn')
p = remote('127.0.0.1',50656)

libc = cdll.LoadLibrary("libc.so.6")
libc.srandom(localtime().tm_yday - 1)

for _ in range(12):
    p.sendlineafter(b'\n',str(libc.random()%90000+10000).encode())

p.interactive()
```

