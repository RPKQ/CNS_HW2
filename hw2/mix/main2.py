import random
from lib import Packet, PublicKeyCipher

from himitsu import flag2


def generate_packet(pk, route):
    # Nope, I won't tell you the answer to the previous subtask ;)
    # You only need to know that flag2 is the content to be sent to Chiffon
    pass


def validate_packet(sk, route, packet):
    for i in range(len(route) - 1):
        next_hop, next_packet = packet.decrypt_server(sk[route[i]])
        assert next_hop == route[i+1]
        packet = next_packet
    message = packet.decrypt_client(sk[3])
    assert message == flag2


def main():
    pk, sk = {}, {}
    pk[0], sk[0] = PublicKeyCipher.gen_key() # server0
    pk[1], sk[1] = PublicKeyCipher.gen_key() # server1
    pk[2], sk[2] = PublicKeyCipher.gen_key() # server2
    pk[3], sk[3] = PublicKeyCipher.gen_key() # Chiffon

    print(f'The public key of server0 is {pk[0]}')
    print(f'The public key of server1 is {pk[1]}')
    print(f'The public key of server2 is {pk[2]}')
    print(f'The public key of Chiffon is {pk[3]}')
    print()

    route = [random.choice([0, 1, 2])]
    while len(route) < 5:
        route.append(random.choice([i for i in range(3) if i != route[-1]]))
    route.append(3)

    packet = generate_packet(pk, route)
    validate_packet(sk, route, packet)

    print(f'You eavesdrop Bob\'s traffic and get the following packet:')
    print(packet)


if __name__ == '__main__':
    main()

