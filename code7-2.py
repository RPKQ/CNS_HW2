import socket
import socks


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

# import base64, hashlib

# with open("hw2/tor/pubkey", "rb") as f:
#     pk = f.read(100)[32:]
#     H = hashlib.sha3_256()
#     H.update(b".onion checksum"+ pk + b'\x03') 
#     checksum = H.digest()[:2]
#     onion_address = base64.b32encode(pk+checksum+b'\x03') + b".onion"
#     print(onion_address.decode().lower())


socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "localhost", 9050, True)
s = socks.socksocket()
s.connect('http://cnshwur3vd6rdqotatnt3rhhdaxiq54lury2qkpttk64dlisvmdls3qd.onion', 8002)
# s.sendall('Hello world')
print(s.recv(1024))
