# Python3
from secret import flag
import random
import base64

pool = 'qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM'
r = random.randint(2, 250)
assert flag.startswith('hsctf{')


def generate(length):
    return ''.join(random.choices(pool, k=length))


def f(x):
    random.seed(x)
    return random.getrandbits(8)


def encrypt(plaintext, key):
    plaintext = list(map(ord, plaintext))
    for _ in range(20):
        key = f(key)
        assert key != 0
    for i in range(len(plaintext)):
        key = f(key)
        tmp = (key * r) % 251
        assert tmp != 0 and key != 0
        plaintext[i] = plaintext[i] ^ tmp
    plaintext = bytes(plaintext)
    return base64.b64encode(plaintext)


m = generate(random.randint(200, 300)) + flag + generate(random.randint(200, 300))
c = encrypt(m, random.getrandbits(128))
print(c)
# b'8OcTbAfL6/kOMQnC9v8SNmmSzvQMeGTT8vANM1T+7vIce2fo0fc2RnScrNxTSmeSyuMjMF//w8BWaXX91dsGcnvmreg0NQTw96ceVVXj3sQ3Znn51OU1S0bOyaMtNHTj36AcWFqewN4zRUXD6agGbAPE+tQtd3XG0doAa1Ll9fhcQ1zk0McTM1bv8PIQOAnn3vQ3UgLD3PsONXLs4KkXMnjTyMEQOFn/0uYVUwOY1PsleEHCyNopRVDr+Kc0e2PH9v0XNXfprfIPU3nw7KYTNX/G7twLSkHoyaUlQHXi3v02UHmdy/4iNgme3Pc8bgPp+tYWV1+YzPkXYkXM4ulUc27DrM4SNUPT2fQlckj1qP4Fal+YoPYJMlyZ8qhXfF3Y0tUDdUXl3vg0dFTi++VVOFfH/dgMS1ru9N8WU0HF9cUCTgPe+qVdSn/u7Mkda0GTw/QDcWPZ9KYGN2jSzfk0OVrMzt0yRHD64KMrUgPF2sFWcmP56KZSTAD61PUGeXrd49MgU1bL8OsVNWj91vIsalXwqf0qaWbwzv0lWETA4eElS3L99cYmU1nv9dRQTWbDyclScQTN6NIhV2j//+ZWbH7Z68kwM3Dy4dcUc1PQy8kRTl/4zcU9WGWfoakOMXuf69MXZQTEz+kJT1Dar8UN'
