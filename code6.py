import hashlib, hmac
from Crypto.Cipher import AES


class Interpreter:

    def __init__(self, nonce_client:bytes, nonce_server:bytes, enc_premaster_secret:bytes, d:int, n:int) -> None:
        self.d = d
        self.n = n
        self.update(nonce_client, nonce_server, enc_premaster_secret)

    # https://www.cryptologie.net/article/340/tls-pre-master-secrets-and-master-secrets/
    @staticmethod
    def PRF(secret: bytes, label: bytes, seed: bytes, required_len: int) -> bytes:
        A = []
        A.append(label + seed)
        ret = bytes()
        while 1 :
            A_new = hmac.new(secret, A[len(A)-1], hashlib.sha256).digest()
            A.append(A_new)
            ret = ret + hmac.new(secret, A_new + A[0], hashlib.sha256).digest()
            if len(ret) >= required_len:
                break
        return ret[:required_len]

    def update(self, nonce_client:bytes, nonce_server:bytes, enc_premaster:bytes) -> None:

        MAC_KEY_LEN = 20
        WRITE_KEY_LEN = 32

        premaster = pow(enc_premaster, self.d, self.n)
        premaster = bytes.fromhex(str(hex(premaster))[-96:])

        master_secret = self.PRF(premaster, b"master secret", nonce_client + nonce_server, 48)
        # print("master secret: ", master_secret)

        key_block = self.PRF(master_secret, b"key expansion", nonce_server + nonce_client, 2*MAC_KEY_LEN + 2*WRITE_KEY_LEN)
        # print("key_block: ", key_block)

        self.client_MAC_key = key_block[0:MAC_KEY_LEN]
        self.server_MAC_key = key_block[MAC_KEY_LEN:2*MAC_KEY_LEN]
        self.client_write_key = key_block[2*MAC_KEY_LEN:2*MAC_KEY_LEN + WRITE_KEY_LEN]
        self.server_write_key = key_block[2*MAC_KEY_LEN + WRITE_KEY_LEN:2*MAC_KEY_LEN + 2*WRITE_KEY_LEN]
        # print("client_write_key: ", client_write_key)
    
    def decrypt_server(self, enc_msg:bytes) -> bytes:
        iv = enc_msg[:16]
        enc_msg = enc_msg[16:]

        cipher = AES.new(self.server_write_key, AES.MODE_CBC, iv=iv)
        return cipher.decrypt(enc_msg)

    def decrypt_client(self, enc_msg:bytes) -> bytes:
        iv = enc_msg[:16]
        enc_msg = enc_msg[16:]

        cipher = AES.new(self.client_write_key, AES.MODE_CBC, iv=iv)
        return cipher.decrypt(enc_msg)

### get private key ###

p = 17976582969685758201663919950989219845198681525302584881782788933895992966002672620127825946786386174714336373829910219221794776439396464172315795797908440846556422487799588512111711928525632749797143212057727911759598187415282223426893718673678372395954522051287819871807004135376622419777234478252341286161977130938991463423813179823397276073457293447695985715943195766978233882025321226982428629691756874554104230180902605850328639093904864625506257530611622940563953184214854003909540141731630648366547163459117146799026215058939570041459494744653011490185284137047426865672297031964678101356343117265206545020597
q = 17976582969685758201663919950989219845198681525302584881782788933895992966002672620127825946786386174714336373829910219221794776439396464172315795797908440846556422487799588512111711928525632749797143212057727911759598187415282223426893718673678372395954522051287819871807004135376622419777234478252341286161977130938991463423813179823397276073457293447695985715943195766978233882025321226982428629691756874554104230180902605850328639093904864625506257530611622940563953184214854003909540141731630648366547163459117146799026215058939570041459494744653011490185284137047426865672297031964678101356443117265206545020727
n = p*q
phi = (p-1)*(q-1)
e = 65537
d = pow(e, -1, phi)

nonce_client = bytes.fromhex("10e3537daf03fdcc3392361986937fb9306d5425b34a61acf70ecacaf05490c3")
nonce_server = bytes.fromhex("e5624ac894c1133a675a7e57bb1dca798686034db8f8c28a444f574e47524401")
enc_premaster = int(0x018f3485b6b31fc2953321f12f4bfeb172a7da2e3cdd4b7605b03ccf6c141dabc13449d2c16b4cebc1b779bf826184343ec3d4ac223c30cc9f2afb397d288abb7be4d27a15e447136c2766cf96b5a37c1463573576486bd2a6975e37483a1ea2df91a0fcc23efea159cc2df35c3e7c7d86db4db7a609f31c378e095955fc737e244161b546ab99319804473a1b46aab5517a6b84f0fe0849168c63397f6bfb84b8b742cbc4a842f578aa17ce2d3494873f2754872309d0dd1b0a6bca0bbe900a5d5643081b3db82884da8cee09a05f44672a7ebde4002be2ecb356f46c1fab2f7dd493d11d9741130e349a53d542189bdce66fd498efe45dcb8dd4f8bdc414d7e0e1ce086e6aa255416d7c264e1e58d08a6f7e8f29b35d61968c501b52c235a0fafade1502671488595307a3ca78af320cfeb53f7716b3157bc39ef3daaf2418a392c8e118f961320eab29bb47e301c08d86157db3216b64a9960fc417551858e9805676b61daadd6ba4dc73fba0758e45be21b1cd80c9c047517cf1f195c6228c7f68db775f599817c5d72052b57d0a8ab68d39a12a1ca2251fcc31ddda5286e453c91b7b21c17fc2e2fd87ebb16462bb080719fb92f53faa92bd3d4377044313b0ec1ede28260f000d9358f99bc6d6199c18cdfb21b26369dc304ebc0ebb7ec5f3ffa18a0542c3a9f8c0e1229af6d6eb0c957127fcde38f7dceea3422833eb)

interpreter = Interpreter(nonce_client, nonce_server, enc_premaster, d, n)

# 0: server -> client
# 1: client -> server
msg = [(0, "76c2d9ac430ebc34390dce82af3b283aa8dcb7d9bbd9184c091a1d75270b97510ff40c9de42ac401ca576072ea2aeff70a2c3934a55796192584ecbab6f2f6bf"),
        (0, "c1da0b2dd50d9e123c6a667c2cd244a64b11c2eaf3be29266a414636517e7f7d66e1aac568934f89b79e363a93a2e8d4a3fd25665364c22cebc32ac29c39674e"),
        (0, "22e33283955ce7d594f3eadb35d9cff2876230ae04338ed1fdfac68aa5eda1df68f81e03b3d2580750cadadef993d463ddedd08a7ab720ecd879a72b25a97077"),
        (0, "0172cf9cbd49611d07b1b18a432466e6a48c6ec20cf7eeec79ed3db45347d362265aef6ad63e6ffaa1d970a56558c5ab"),
        (1, "5cf9d35b51ecbf2342637d295f6b1f707e2229c39d906e505640c09237981d471856349c44e60633f67f61e5a7dea994"),
        (0, "f53a717db2d09b567c76b25baca3fe2b9040b61b000cd6f617853299ad247ac8f2f1f0100c3601a0bc73399b4735f1c3"),
        (1, "a58a0740a2a5cac6a4c17d29ef6bd7297c20e435650092cb7e3b42618579a77d1864d8d7cfc123920e4055f3ed0d8ca00bb0ed06e631399fc1290b433692ba5f"),
        (0, "fcda3e537597e4e034482fda53f238a3d0f6f04ed616a18b19c3f7ad518e97ad592e010f7a8427debfd0fd4ebb332712534e5e0fb56f5cee54e1043b7b982442"),
        (1, "d14f5bf6f495c299a69832ccd7dc3b20431228ea0d21a98c715725874a2dc23a732e970f9597483c7b3ad75dcb6a14ec10868612515be20834c9e006d1833d36")]

for (f, m) in msg:
    m = bytes.fromhex(m)
    if f == 0:
        print(interpreter.decrypt_server(m))
    else:
        print(interpreter.decrypt_client(m))