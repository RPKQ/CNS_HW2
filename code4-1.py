from pwn import *
from hw2.mix.lib import Packet
import binascii
from hw2.mix.cipher2 import StreamCipher, PublicKeyCipher, randbytes


# bob = remote('cns.csie.org', 9004)

# get pk, sk of server
# pk = {}
# pk[0] = (int(bob.recvline().split()[6][1:-1]), 65537) # server0
# pk[1] = (int(bob.recvline().split()[6][1:-1]), 65537) # server1
# pk[2] = (int(bob.recvline().split()[6][1:-1]), 65537) # server2
# pk[3] = (int(bob.recvline().split()[6][1:-1]), 65537) # server3
# print(pk)
# print(sk)

pk, sk = {}, {}
pk[0], sk[0] = PublicKeyCipher.gen_key() # server0
pk[1], sk[1] = PublicKeyCipher.gen_key() # server1
pk[2], sk[2] = PublicKeyCipher.gen_key() # server2
pk[3], sk[3] = PublicKeyCipher.gen_key() # Bob


# get route
# bob.recvuntil(b"The route of the packet should be ")
# route = str(bob.recvline()[1:17])
# tmp = []
# for i in route:
#     if i.isdigit():
#         tmp.append(int(i))
# route = tmp
# print("route: ", route)

route = [1, 2, 1, 0, 1, 3]

# get packet
message = b"Give me flag, now!"
packet = Packet.create(message, 3, pk[3])
print(packet.decrypt_client(sk[3]))

# for send_to in route[::-1][1:]:
#     print("add to: ", send_to)
#     packet.add_next_hop(send_to, pk[send_to])

# send packet
# bob.sendlineafter(b">", binascii.hexlify(packet.data))
# bob.interactive()