from pwn import *
import random, time

bob = remote('cns.csie.org', 8016)
random.seed(int(time.time()))

# Bob: flag 2
bob.sendlineafter(b"Your choice: ", b'2')

# get p, g, y, h
bob.recvuntil(b"p = ")
p = int(bob.recvline().strip())
# print("p = ", p)
bob.recvuntil(b"g = ")
g = int(bob.recvline().strip())
bob.recvuntil(b"y = ")
y = int(bob.recvline().strip())
bob.recvuntil(b"h = ")
h = int(bob.recvline().strip())

# get c by random(int(time.time()))
# print(int(time.time()))
random.randint(1, p-1)    # h

# send z, a, b
z = 1
bob.sendlineafter(b"z = ", str(z).encode())
c = random.randint(1, p-2)    # c
# print("c =", c)
a = pow(y, -c, p)
bob.sendlineafter(b"a = ", str(a).encode())
b = 1
bob.sendlineafter(b"b = ", str(b).encode())

# check c
bob.recvuntil(b"c = ")
c = int(bob.recvline().strip())
# print("c = ", c)

#
w = p-1
bob.sendlineafter(b"w = ", str(w).encode())

print(bob.recvline().strip().decode())