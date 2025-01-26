from Crypto.Util.number import *
import random
flag=b'BaseCTF{}'
m=bytes_to_long(flag)
bin_m=bin(m)[2:]
length=len(bin_m)

a=[1]
sum=1
for i in range(length-1):
    temp=random.randint(2*sum+1,4*sum)
    sum=sum+temp
    a.append(temp)

a=a[::-1]
c=0
for i in range(length):
    if bin_m[i]=='1':
        c=c+a[i]
print("a=",a)
print("c=",c)