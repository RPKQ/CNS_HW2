from pwn import *

alice = remote('cns.csie.org', 8015)
bob = remote('cns.csie.org', 8016)

# Bob: flag 1
bob.sendlineafter(b"Your choice: ", str(1))

# Bob -> Alice: h 
bob.recvuntil(b"h = ")
h = bob.recvline().strip()
alice.sendlineafter(b"h = ", h)

# Alice -> Bob: z, a, b
alice.recvuntil(b"z = ")
z = alice.recvline().strip()
bob.sendlineafter(b"z = ", z)

alice.recvuntil(b"a = ")
a = alice.recvline().strip()
bob.sendlineafter(b"a = ", a)

alice.recvuntil(b"b = ")
b = alice.recvline().strip()
bob.sendlineafter(b"b = ", b)

# Bob -> Alice: c
bob.recvuntil(b"c = ")
c = bob.recvline().strip()
alice.sendlineafter(b"c = ", c)

# Alice -> Bob: w
alice.recvuntil(b"w = ")
w = alice.recvline().strip()
bob.sendlineafter(b"w = ", w)

# get flag
bob.recvuntil(b"I think you're Alice.")
print(bob.recvline().strip().decode())
