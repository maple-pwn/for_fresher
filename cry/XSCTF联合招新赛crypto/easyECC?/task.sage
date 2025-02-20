from secret import flag
import random

bits = 64
p = random_prime(2^bits)
a = randint(1, bits)
b = randint(1, bits)
E = EllipticCurve(GF(p), [a, b])
g = E.random_element()

x = random_prime(2^16)
pk = x*g
k = randint(1, p-1)
kPoint = k*pk
kp = kPoint.xy()

c = []
for i in range(len(flag)):
  c.append( (ord(flag[i]) ^^ int(kp[i%2])) & 0xff )
c = bytes(c).hex()

print(p)
print(a)
print(b)
print(g)
#print(g.order())
print(c)

# 4698491801183562589
# 58
# 59
# (2965797230620625775 : 4310564666276679314 : 1)
# ac73a774a25bd512d543dc468542c9428141800dd041d043c918d112850dd515d6128214d1138211d71599
