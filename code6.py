import hashlib, hmac
from http import client

### get private key ###

p = 17976582969685758201663919950989219845198681525302584881782788933895992966002672620127825946786386174714336373829910219221794776439396464172315795797908440846556422487799588512111711928525632749797143212057727911759598187415282223426893718673678372395954522051287819871807004135376622419777234478252341286161977130938991463423813179823397276073457293447695985715943195766978233882025321226982428629691756874554104230180902605850328639093904864625506257530611622940563953184214854003909540141731630648366547163459117146799026215058939570041459494744653011490185284137047426865672297031964678101356343117265206545020597
q = 17976582969685758201663919950989219845198681525302584881782788933895992966002672620127825946786386174714336373829910219221794776439396464172315795797908440846556422487799588512111711928525632749797143212057727911759598187415282223426893718673678372395954522051287819871807004135376622419777234478252341286161977130938991463423813179823397276073457293447695985715943195766978233882025321226982428629691756874554104230180902605850328639093904864625506257530611622940563953184214854003909540141731630648366547163459117146799026215058939570041459494744653011490185284137047426865672297031964678101356443117265206545020727
n = p*q
phi = (p-1)*(q-1)
e = 65537
d = pow(e, -1, phi)

### get premaster secret ###

nonce_client_1 = bytes.fromhex("eff5ac9b1572abd0bad4eff7de901a609fd43e02029d6d082735910d9854e3a8")
nonce_server_1 = bytes.fromhex("8d301e416ce0d0d669ea409c9be5e0ad83a8dad3516d536b444f574e47524401")
encrypted_premaster = int(0x1535e8f420862286d0d61bcce92942706fc261fdcf5f66dfbd1cb4afb515bb93248112af5f65981119a49f1f42569a8fb96b3f4b842d99057d7a9722fc615992acd0c3fe42ca16ed19e08e67ff83b72b21a5fa58380cca9fc645d53f580ca0a88487955d8066f967065330c6398a1276d9e51f377dc30ab175d05710f668826f788f995b93534b1911082c5ed4016ce346b842a2c6876a97ef31993fc2ae1d16b4fe3429e1e3967198d4826b188fddbef26eb4a4ba123efe311501e1781062f3b81fbea2f2c6e7cba6163b8c88d6690a962ddb4c000824d8d7607ac4fe0e41f94cf3e8a4df47966f192142d9ef0e91b7bec7c3a641ddabe9916c08ccf434a9e13fc370332f6790af0adb930f9db09ba2c8dea4a6414a0a845377369d6adc93dcf03dd0551a5be7da23ac15e0c5c2d48ed465de663e52ad43580b45272b427e7ced55b39d1ee7d43a349e4fa22cddbb35c1dd48bf8df318af6f25470e4cbb78c7c85cfe863c95eb7b7ebd0ffd272c3d7b0ddcd98a1a74b168dceb61ae07e0ee60b964f1561a260945db00f7a559edb3050f7e6907abb34324d998c87a396757184be5264e8be46afa04665262bb111138c908cbe103274bfb33ab9a44d2360f313b76dbcda0bbda0084cdfe14bd741482e7eb3e2c50928044e0b14db7a6b5418dca0a5ac156c0779f8d06ce444dbd007f46214959f1ec19914a810e094c6a79a6)
premaster = pow(encrypted_premaster, d, n)
premaster = bytes.fromhex(str(hex(premaster))[-96:])
print("premaster:", premaster)

### derive master secrete from premaster secret ###


# https://www.cryptologie.net/article/340/tls-pre-master-secrets-and-master-secrets/
def PRF(secret: bytes, label: bytes, seed: bytes, required_len: int):
    A = []
    A.append(label + seed)
    ret = bytes()
    while 1 :
        A_new = hmac.new(secret, A[len(A)-1], hashlib.sha256).digest()
        A.append(A_new)
        ret = ret + hmac.new(secret, A_new + A[0], hashlib.sha256).digest()
        if len(ret) >= required_len:
            break
    # print(A)
    return ret[:required_len]


master_secret = PRF(premaster, b"master secret", nonce_client_1 + nonce_server_1, 48)
# print("master secret: ", master_secret)

### derive key from master secret ###

MAC_KEY_LEN = 20
WRITE_KEY_LEN = 32
# IV_KEY_LEN = 16

key_block = PRF(master_secret, b"key expansion", nonce_server_1 + nonce_client_1, 2*MAC_KEY_LEN + 2*WRITE_KEY_LEN)
print("key_block: ", key_block)

client_MAC_key = key_block[0:MAC_KEY_LEN]
server_MAC_key = key_block[MAC_KEY_LEN:2*MAC_KEY_LEN]
client_write_key = key_block[2*MAC_KEY_LEN:2*MAC_KEY_LEN + WRITE_KEY_LEN]
server_write_key = key_block[2*MAC_KEY_LEN + WRITE_KEY_LEN:2*MAC_KEY_LEN + 2*WRITE_KEY_LEN]
# print("client_write_key: ", client_write_key)

enc_client_msg = bytes.fromhex("90c5cecab966216e947d49fb5dec94368cd4d94559043136b82955e949a0483e259efed9f9ca50a005ae1c96c6637cd7")
client_iv = enc_client_msg[:16]
enc_client_msg = enc_client_msg[16:]
print("client iv: ", client_iv)
print("enc_client_msg: ", enc_client_msg)


enc_server_msg = bytes.fromhex("7aabd5d4538727c03e998a493c67d1ff17668c45a03ef4ab091dc80265f30d6ef0f73ad1da9eb7709b2aafc1e40c0f20257aaf2d87261927e5c7609cb2ed4d0b")
server_iv = enc_server_msg[:16]
enc_server_msg = enc_server_msg[16:]
print("server iv: ", server_iv)
print("enc_server_msg: ", enc_server_msg)


from Crypto.Cipher import AES

cipher = AES.new(client_write_key, AES.MODE_CBC, iv=client_iv)
client_msg = cipher.decrypt(enc_client_msg)
print("client_msg: ", client_msg)

cipher = AES.new(server_write_key, AES.MODE_CBC, iv=server_iv)
server_msg = cipher.decrypt(enc_server_msg)
print("server_msg: ", server_msg)