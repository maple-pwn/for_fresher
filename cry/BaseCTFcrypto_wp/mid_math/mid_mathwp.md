# BaseCTF CRYPTO方向mid_math

打开题目后发现是数学题，和前面的ez_math一样与矩阵计算和行列式计算有关。

首先理解题目的加密算法，是将flag转换为长整型，通过复杂的矩阵运算进行加密。

理解了加密算法，就可以解决这道题了。

而且解密方式类似于ez_math中的矩阵与行列式的性质。

同时c*d=point2，point1和point2均已知。

所以|A|=flag*(ad-bc)=flag*(point1-point2),所以问题在于计算C和B的行列式值。

我们很容易发现C和B都是由对角矩阵相乘得到的，所以C和B的行列式值均为1.

综上，我们可以得到flag的数值，即解决了这个问题。

```python
det=a11*(a22*a33-a23*a32)-a12*(a21*a33-a23*a31)+a13*(a21*a32-a22*a31)
```

这步就是计算MAT的行列式值

```python
flag=det//(point1-point2)
```

这步具体解出flag值，问题解决
