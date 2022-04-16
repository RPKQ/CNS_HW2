import random
import hashlib
from binascii import unhexlify

def prover_interactive(p, g, y, x):
    print('==========Zero knowledge proof of CDH==========')
    print('My public key:')
    print(f'p = {p}')
    print(f'g = {g}')
    print(f'y = {y}')
    print('Give me an element in Z_p^*')
    try:
        h = int(input('h = '))
        assert h > 0 and h < p
    except:
        print('Invalid input.')
        return
    z = pow(h, x, p)
    print(f'z = {z}')
    r = random.randint(1, p-2)
    a = pow(g, r, p)
    b = pow(h, r, p)
    print(f'a = {a}')
    print(f'b = {b}')
    print('Give me the challenge')
    try:
        c = int(input('c = '))
    except:
        print('Invalid input.')
        return
    w = c * x + r
    print(f'w = {w}')

def verifier_interactive(p, g, y):
    print('==========Show me your knowledge of CDH==========')
    h = random.randint(1, p-1)
    print(f'h = {h}')
    try:
        z = int(input('z = '))
        assert z > 0 and z < p
        a = int(input('a = '))
        assert a > 0 and a < p
        b = int(input('b = '))
        assert b > 0 and b < p
    except:
        print('Invalid input.')
        return False
    c = random.randint(1, p-2)
    print(f'c = {c}')
    try:
        w = int(input('w = '))
    except:
        print('Invalid input.')
        return False

    if pow(g, w, p) == (pow(y, c, p) * a) % p \
        and pow(h, w, p) == (pow(z, c, p) * b) % p:
        return True
    else:
        return False

def H(param1, param2):
    # combine two sha256 output to make it 512 bits
    sha256 = hashlib.sha256()
    sha256.update(str(param1).encode())
    output1 = unhexlify(sha256.hexdigest())
    sha256.update(str(param2).encode())
    output2 = unhexlify(sha256.hexdigest())
    return int.from_bytes(output1 + output2, 'big')

def prover_non_interactive(p, g, y, x):
    print('==========Zero knowledge proof of CDH==========')
    print('My public key:')
    print(f'p = {p}')
    print(f'g = {g}')
    print(f'y = {y}')
    print('Give me an element in Z_p^*')
    try:
        h = int(input('h = '))
        assert h > 0 and h < p
    except:
        print('Invalid input.')
        return
    z = pow(h, x, p)
    print(f'z = {z}')
    r = random.randint(1, p-2)
    a = pow(g, r, p)
    b = pow(h, r, p)
    print(f'a = {a}')
    print(f'b = {b}')
    c = H(h, b)
    w = c * x + r
    print(f'w = {w}')

def verifier_non_interactive(p, g, y):
    print('==========Show me your knowledge of CDH==========')
    h = random.randint(1, p-1)
    print(f'h = {h}')
    try:
        z = int(input('z = '))
        assert z > 0 and z < p
        a = int(input('a = '))
        assert a > 0 and a < p
        b = int(input('b = '))
        assert b > 0 and b < p
        w = int(input('w = '))
    except:
        print('Invalid input.')
        return False

    c = H(h, b)
    if pow(g, w, p) == (pow(y, c, p) * a) % p \
        and pow(h, w, p) == (pow(z, c, p) * b) % p:
        return True
    else:
        return False
