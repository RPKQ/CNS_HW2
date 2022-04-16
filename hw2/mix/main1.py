import random
import time
from lib import Packet, PublicKeyCipher

from himitsu import flag1


def main():
    pk, sk = {}, {}
    pk[0], sk[0] = PublicKeyCipher.gen_key() # server0
    pk[1], sk[1] = PublicKeyCipher.gen_key() # server1
    pk[2], sk[2] = PublicKeyCipher.gen_key() # server2
    pk[3], sk[3] = PublicKeyCipher.gen_key() # Bob

    print(f'The public key of server0 is {pk[0]}')
    print(f'The public key of server1 is {pk[1]}')
    print(f'The public key of server2 is {pk[2]}')
    print(f'The public key of Bob is {pk[3]}')
    print()

    route = [random.choice([0, 1, 2])]
    while len(route) < 5:
        route.append(random.choice([i for i in range(3) if i != route[-1]]))
    route.append(3)

    print(f'Send the message "Give me flag, now!" to Bob')
    print(f'The route of the packet should be {route}, where 3 stands for Bob')
    print(f'Now, send packet to server{route[0]} (hex encoded):')
    raw = input('> ')
    packet = Packet(bytes.fromhex(raw))

    print(f'processing ...')
    time.sleep(1)

    try:
        for i in range(len(route) - 1):
            next_hop, next_packet = packet.decrypt_server(sk[route[i]])
            assert next_hop == route[i+1]
            packet = next_packet
        message = packet.decrypt_client(sk[3])
        assert message == b'Give me flag, now!'
    except:
        print(f'Bob: I cannot hear you!')
        exit()

    print(f'Bob: {flag1}')


if __name__ == '__main__':
    main()

