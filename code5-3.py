from pwn import *
import hashlib
from binascii import unhexlify


def H(param1, param2):
    # combine two sha256 output to make it 512 bits
    sha256 = hashlib.sha256()
    sha256.update(str(param1).encode())
    output1 = unhexlify(sha256.hexdigest())
    sha256.update(str(param2).encode())
    output2 = unhexlify(sha256.hexdigest())
    return int.from_bytes(output1 + output2, 'big')

bob = remote('cns.csie.org', 8016)

# Bob: flag 2
bob.sendlineafter(b"Your choice: ", str(3))

# get p, g, y, h
bob.recvuntil(b"p = ")
p = int(bob.recvline().strip())
bob.recvuntil(b"g = ")
g = int(bob.recvline().strip())
bob.recvuntil(b"y = ")
y = int(bob.recvline().strip())
bob.recvuntil(b"h = ")
h = int(bob.recvline().strip())

# get c by random(int(time.time()))
random.randint(1, p-1)    # h

# send z, a, b
z = 1
b = 1
c = H(h, b)
a = pow(y, -c, p)
bob.sendlineafter(b"z = ", str(z))
bob.sendlineafter(b"a = ", str(a))
bob.sendlineafter(b"b = ", str(b))

#
w = p-1
bob.sendlineafter(b"w = ", str(w))

print(bob.recvline().strip().decode())





