from pwn import *
import random, time
import hashlib
from binascii import unhexlify

def task5_1(alice, bob):
        
    # Bob: flag 1
    bob.sendlineafter(b"Your choice: ", b"1")

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

def task5_2(bob):
    
    random.seed(int(time.time()))

    # Bob: flag 2
    bob.sendlineafter(b"Your choice: ", b'2')

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
    bob.sendlineafter(b"z = ", str(z).encode())
    c = random.randint(1, p-2)    # c
    # print("c =", c)
    a = pow(y, -c, p)
    bob.sendlineafter(b"a = ", str(a).encode())
    b = 1
    bob.sendlineafter(b"b = ", str(b).encode())

    # check c
    # bob.recvuntil(b"c = ")
    # c = int(bob.recvline().strip())
    # print("c = ", c)

    #
    w = p-1
    bob.sendlineafter(b"w = ", str(w).encode())

    print(bob.recvline().strip().decode())

def task5_3(bob):
    def H(param1, param2):
        # combine two sha256 output to make it 512 bits
        sha256 = hashlib.sha256()
        sha256.update(str(param1).encode())
        output1 = unhexlify(sha256.hexdigest())
        sha256.update(str(param2).encode())
        output2 = unhexlify(sha256.hexdigest())
        return int.from_bytes(output1 + output2, 'big')

    # Bob: flag 2
    bob.sendlineafter(b"Your choice: ", b'3')

    # get p, g, y, h
    bob.recvuntil(b"p = ")
    p = int(bob.recvline().strip())
    bob.recvuntil(b"g = ")
    g = int(bob.recvline().strip())
    bob.recvuntil(b"y = ")
    y = int(bob.recvline().strip())
    bob.recvuntil(b"h = ")
    h = int(bob.recvline().strip())

    # send z, a, b
    z = 1
    b = 1
    c = H(h, b)
    a = pow(y, -c, p)
    bob.sendlineafter(b"z = ", str(z).encode())
    bob.sendlineafter(b"a = ", str(a).encode())
    bob.sendlineafter(b"b = ", str(b).encode())

    #
    w = p-1
    bob.sendlineafter(b"w = ", str(w).encode())

    print(bob.recvline().strip().decode())

def task5_4(bob):

    # Bob: flag 2
    bob.sendlineafter(b"Your choice: ", b'4')

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


alice = remote('cns.csie.org', 8015)
bob = remote('cns.csie.org', 8016)

task5_1(alice, bob)
task5_2(bob)
task5_3(bob)
task5_4(bob)