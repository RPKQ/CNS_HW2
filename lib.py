from cipher2 import StreamCipher, PublicKeyCipher, randbytes


def i2b(n): # int to bytes
    return f'{n:20d}'.encode()


class Packet:
    def __init__(self, data):
        assert len(data) == 400
        self.data = data

    def __repr__(self):
        return f'Packet({self.data})'

    @staticmethod
    def create(message, send_to, pk):
        assert len(message) <= 40
        message = message.ljust(400, b'\x00')
        
        # encrypt data with one-time key
        k = randbytes(16)
        k = int.from_bytes(k, "big") % pk[3][0]
        data = StreamCipher.encrypt(k, message[:-32])
        
        # encrypt one-time key with pk
        c_k = PublicKeyCipher.encrypt(pk[3], k)
        data = c_k + data

        # add hops
        packet = Packet(data)
        for i in range(len(send_to)-2, -1, -1):
            packet.add_next_hop(send_to[i+1], pk[send_to[i]])

        assert len(packet.data) == 400
        return packet

    def add_next_hop(self, target, pk):
        # TODO

        # print(f"add hop {target}")

        # encrypt data with one-time key
        k = randbytes(16)
        k = int.from_bytes(k, "big") % pk[0]
        self.data = StreamCipher.encrypt(k, str(target).rjust(20, "0").encode() + self.data[:-52])
        
        # encrypt one-time key with pk
        c_k = PublicKeyCipher.encrypt(pk, k)
        self.data = c_k + self.data

        assert len(self.data) == 400

    def decrypt_client(self, sk):
        assert len(self.data) == 400
        tmp, cipher = self.data[:32], self.data[32:]
        one_time_key = PublicKeyCipher.decrypt(sk, tmp)
        return StreamCipher.decrypt(one_time_key, cipher)[:40].strip(b'\x00')

    def decrypt_server(self, sk):
        assert len(self.data) == 400
        tmp, cipher = self.data[:32], self.data[32:]
        one_time_key = PublicKeyCipher.decrypt(sk, tmp)
        tmp = StreamCipher.decrypt(one_time_key, cipher)
        send_to, next_cipher = int(tmp[:20]), (tmp[20:] + randbytes(52))
        return send_to, Packet(next_cipher)


class Server:
    def __init__(self, sk):
        self.sk = sk
        self.recv_buffer = []

    def recv(self, packet):
        self.recv_buffer.append(packet)
        if len(self.recv_buffer) >= 3:
            self.recv_buffer, processing_buffer = [], self.recv_buffer
            for packet in processing_buffer:
                send_to, next_packet = packet.decrypt_server(self.sk)
                self.send_to_server(send_to, next_packet)

    def send_to_server(self, target, packet):
        pass
