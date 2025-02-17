import gmpy2
key = 'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890{}_#&'
c = 'WhcuU0o4Vc0VUasJc08W04uJ0qd2IJpVJ02V04p'
y_1 = key.index('W')
y_2 = key.index('h')
x_1 = key.index('f')
x_2 = key.index('{')
k = ((y_1-y_2)*gmpy2.invert(x_1-x_2,len(key)))%len(key)
r = (y_1-k*x_1)%len(key)
flag=[]
for m in c:
    y = key.index(m)
    x = ((y-r)*gmpy2.invert(k,len(key)))%len(key)
    flag.append(key[x])
result = ''.join(flag)  
print(result)