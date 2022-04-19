from pwn import *
import random, time

bob = remote('cns.csie.org', 8016)

# Bob: flag 2
bob.sendlineafter(b"Your choice: ", str(4).encode())

# get p, g, y, h
bob.recvuntil(b"p = ")
p = int(bob.recvline().strip())
bob.recvuntil(b"g = ")
g = int(bob.recvline().strip())
bob.recvuntil(b"y = ")
y = int(bob.recvline().strip())
bob.recvuntil(b"h = ")
h = int(bob.recvline().strip())

x = 4955443778776036716256191344604504647502861925880052553262118920576335648554926844698019686656852223900095990229865138812451265325069898790688422886552274

r = random.randint(1, p-2)

# send z, a, b
z = pow(h, x, p)
a = pow(g, r, p)
b = pow(h, r, p)
bob.sendlineafter(b"z = ", str(z).encode())
bob.sendlineafter(b"a = ", str(a).encode())
bob.sendlineafter(b"b = ", str(b).encode())

# get c
bob.recvuntil(b"c = ")
c = int(bob.recvline().strip())
# print("c = ", c)

#
w = c*x + r 
bob.sendlineafter(b"w = ", str(w).encode())

print(bob.recvline().strip().decode())


