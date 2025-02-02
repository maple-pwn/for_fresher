## CRe

###### 1.首先发现文件无法运行，使用010editor查看文件

![image-20250202222705667](C:\Users\H2Q\AppData\Roaming\Typora\typora-user-images\image-20250202222705667.png)

发现是PK头而非exe文件头，修改后文件即可正常打开

![image-20250202222845681](C:\Users\H2Q\AppData\Roaming\Typora\typora-user-images\image-20250202222845681.png)

###### 2.查看修改后的可执行文件发现upx加壳，使用官方工具脱壳即可

![image-20250202222955542](C:\Users\H2Q\AppData\Roaming\Typora\typora-user-images\image-20250202222955542.png)

###### 3.脱壳后对文件进行逆向，发现再对话框输入1即可得到提示

![image-20250202223116032](C:\Users\H2Q\AppData\Roaming\Typora\typora-user-images\image-20250202223116032.png)

![image-20250202223151010](C:\Users\H2Q\AppData\Roaming\Typora\typora-user-images\image-20250202223151010.png)

###### 4.发现是路径规划算法题，按题目要求写代码即可，代码如下

~~~python
def max_path_sum(matrix):
    if not matrix or not matrix[0]:
        return 0
    dp = [[0] * 8 for _ in range(8)]
    dp[0][0] = matrix[0][0]
    for j in range(1, 8):
        dp[0][j] = dp[0][j - 1] + matrix[0][j]
    for i in range(1, 8):
        dp[i][0] = dp[i - 1][0] + matrix[i][0]
    for i in range(1, 8):
        for j in range(1, 8):
            dp[i][j] = max(dp[i - 1][j], dp[i][j - 1]) + matrix[i][j]
    return dp[7][7]
lst = [[0, 1, 0, 0, 2, 0, 0, 20],[0, 1, 1, 5, 5, 0, 0, 0],[1, 0, 1, 0, 0, 0, 2, 10],[0, 0, 1, 0, 10, 0, 0, 0],[2, 0, 0, 4, 0, 0, 0, 20],[0, 0, 15, 0, 1, 0, 0, 0],[0, 0, 1, 0, 25, 0, 6, 0],[4, 0, 0, 5, 0, 6, 0, 20]]
print(max_path_sum(lst))
~~~

###### 5.得到结果75，md5加密即可

