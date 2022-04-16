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
        data = message # TODO: create the correct data
        return Packet(data)

    def add_next_hop(self, target, pk):
        # TODO
        pass

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
