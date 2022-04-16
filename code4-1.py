from pwn import *
from hw2.mix.lib import Packet

bob = remote('cns.csie.org', 9004)

# get pk, sk of server
pk, sk = {}, {}
pk[0], sk[0] = int(bob.recvline().split()[6][1:-1]), 65537 # server0
pk[1], sk[1] = int(bob.recvline().split()[6][1:-1]), 65537 # server1
pk[2], sk[2] = int(bob.recvline().split()[6][1:-1]), 65537 # server2
pk[3], sk[3] = int(bob.recvline().split()[6][1:-1]), 65537 # server3
# print(pk)
# print(sk)

# get route
bob.recvline()
bob.recvuntil(b"The route of the packet should be ")
route = str(bob.recvline()[1:17])
tmp = []
for i in route:
    if i.isdigit():
        tmp.append(int(i))
route = tmp
print("route: ", route)

# get packet
message = "Give me flag, now!"
cipher_text = Packet.create(message, route, pk)

# send packet
bob.sendlineafter(b">", cipher_text)
bob.interactive()