#  https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt#L2029
#
#      onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
#      CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
#
#      where:
#        - PUBKEY is the 32 bytes ed25519 master pubkey of the hidden service.
#        - VERSION is a one byte version field (default value '\x03')
#        - ".onion checksum" is a constant string
#        - CHECKSUM is truncated to two bytes before inserting it in onion_address

### GENERATE ADDRESS ###
import base64, hashlib
with open("hw2/tor/pubkey", "rb") as f:
    pk = f.read(100)[32:]
    H = hashlib.sha3_256()
    H.update(b".onion checksum"+ pk + b'\x03') 
    checksum = H.digest()[:2]
    onion_address = base64.b32encode(pk+checksum+b'\x03') + b".onion"
    print("address:", onion_address.decode().lower())

import socks

socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050, True)
s = socks.socksocket()
s.connect(('cnshwur3vd6rdqotatnt3rhhdaxiq54lury2qkpttk64dlisvmdls3qd.onion', 8002))

range = s.recv(1024).decode().split()[-3][-2:]
L = 1
R = pow(2, int(range))
cnt = 0 
while L<=R:
    M = (L+R)//2
    s.sendall((str(M)+'\n').encode())
    res = s.recv(1024)
    cnt += 1
    print(cnt, str(M))
    if b'small' in res:
        L = M+1
        print(res.decode()[:-13])
    elif b'big' in res:
        R = M-1
        print(res.decode()[:-13])
    else:
        print(res.decode())
        break
        