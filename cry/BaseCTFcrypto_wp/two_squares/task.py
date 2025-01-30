from Crypto.Util.number import *
flag=b'BaseCTF{}'
m=bytes_to_long(flag)
p=getPrime(128)
q=getPrime(128)
n=p*q
e=65537
c=pow(m,e,n)
x=p^2+q^2
print("e =",e)
print("c =",c)
print("x =",x)

"""
e = 65537
c = 42330675787206041757903427737108553993012805007294570657461042152628982126538
x = 209479773119142584969854470862023704936857416491817498021871883305658177375498
"""