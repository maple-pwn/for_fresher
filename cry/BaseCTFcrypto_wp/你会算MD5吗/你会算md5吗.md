# BaseCTF CRYPTO方向你会算md5吗

题目的加密很简单，就是将flag中的每个字符计算它们的md5值输出，得到了密文。

虽然md5基于的是hash散列函数，是无法进行逆运算求解出明文的，但我们已经知道了每个md5值是由单个字符计算而来，这就可以让我们对所有常见字符进行爆破，即计算每个字符的md5值从而找到与给定的md5值相同的字符。

所以，我们写脚本的思路也就非常清楚了，遍历所有常见字符

逐一计算字符的md5值，与给定的md5值符合就可直接输出

```python
for i in range(45):
    for j in range(32,127):
        md5_hash = hashlib.md5()
        md5_hash.update(chr(j).encode('utf-8'))
        md5_value = md5_hash.hexdigest()
        if(md5_value==output[i]):
            print(chr(j),end="")
```

这便是代码的核心部分。

值得注意的是，python输出会自动进行换行操作，所以为了让答案好看，我们可以使用额外的指令使其紧邻着输出。