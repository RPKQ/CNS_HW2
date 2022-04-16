from pwn import *
import random, time

bob = remote('cns.csie.org', 8016)

# Bob: flag 2
bob.sendlineafter(b"Your choice: ", str(2))

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
a = pow(y, -c, p)
b = 1
bob.sendlineafter(b"z = ", str(z))
bob.sendlineafter(b"a = ", str(a))
bob.sendlineafter(b"b = ", str(b))

# check c
# bob.recvuntil(b"c = ")
# c = int(bob.recvline().strip())
# print("c = ", c)

#
w = p-1
bob.sendlineafter(b"w = ", str(w))

print(bob.recvline().strip().decode())




