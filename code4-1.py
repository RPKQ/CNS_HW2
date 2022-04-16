from pwn import *
from lib import Packet
import binascii

bob = remote('cns.csie.org', 9004)

# get pk of server
pk = {}
pk[0] = (int(bob.recvline().split()[6][1:-1]), 65537) # server0
pk[1] = (int(bob.recvline().split()[6][1:-1]), 65537) # server1
pk[2] = (int(bob.recvline().split()[6][1:-1]), 65537) # server2
pk[3] = (int(bob.recvline().split()[6][1:-1]), 65537) # server3
# print(pk)

# get route
bob.recvuntil(b"The route of the packet should be ")
route = str(bob.recvline()[1:17])
tmp = []
for i in route:
    if i.isdigit():
        tmp.append(int(i))
route = tmp
# print("route: ", route)

# get packet
message = b"Give me flag, now!"
packet = Packet.create(message, route, pk)

# send packet
bob.sendlineafter(b">", binascii.hexlify(packet.data))
bob.recvline()
print(bob.recvline().decode())

# #### UNIT TEST #### >> k should be Zn
# from lib import PublicKeyCipher, StreamCipher, randbytes
# pk, sk = {}, {}
# pk[0], sk[0] = PublicKeyCipher.gen_key() # server0

# m = b"Give me flag, now!"
# k = randbytes(32)
# k = int.from_bytes(k, "big") % pk[0][0]
# c_m = StreamCipher.encrypt(k, m)
# c_k = PublicKeyCipher.encrypt(pk[0], k)

# k_ = PublicKeyCipher.decrypt(sk[0], c_k)
# m_ = StreamCipher.decrypt(k_, c_m)

# assert k == k_
# assert m == m_