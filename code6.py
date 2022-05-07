import hashlib, hmac
from Crypto.Cipher import AES
import socket
from OpenSSL import SSL


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

#######################
### get private key ###
#######################

p = 17976582969685758201663919950989219845198681525302584881782788933895992966002672620127825946786386174714336373829910219221794776439396464172315795797908440846556422487799588512111711928525632749797143212057727911759598187415282223426893718673678372395954522051287819871807004135376622419777234478252341286161977130938991463423813179823397276073457293447695985715943195766978233882025321226982428629691756874554104230180902605850328639093904864625506257530611622940563953184214854003909540141731630648366547163459117146799026215058939570041459494744653011490185284137047426865672297031964678101356343117265206545020597
q = 17976582969685758201663919950989219845198681525302584881782788933895992966002672620127825946786386174714336373829910219221794776439396464172315795797908440846556422487799588512111711928525632749797143212057727911759598187415282223426893718673678372395954522051287819871807004135376622419777234478252341286161977130938991463423813179823397276073457293447695985715943195766978233882025321226982428629691756874554104230180902605850328639093904864625506257530611622940563953184214854003909540141731630648366547163459117146799026215058939570041459494744653011490185284137047426865672297031964678101356443117265206545020727
n = p*q
phi = (p-1)*(q-1)
e = 65537
d = pow(e, -1, phi)

#################################
### decrypt wireshark message ###
#################################

# 0: server -> client
# 1: client -> server

### session 3 ###

nonce_client = bytes.fromhex("80d929e0b25fe195a4a0f585b2f0c2824e625b84a17d7472b9e0e21297f05f87")
nonce_server = bytes.fromhex("5dc5f7d1a00b1363ee928a77528f1a5cab8eb12005f7e8af444f574e47524401")
enc_premaster = int(0x20f4dc4ccaff2e44d608593152052854401c4f00136c460d9efcd049505fa3408f3597cba1166fceacc95cd9f520c80fe5aa680780b8e3430ea32ffb4dc127152d3104b12183506e2b243f6b83d2c921ae7b801a3629a9e35b30251df0ac3d59274d34fed7c43e145ebdf7b5faa003513f5660473aa60dcaee92656eaf2ffea421db56645464c9cd2284d74fbf97815bef1112d3adb8f481ff7c0b038da021bd0f85efbe681dbd4300e4173bcf4722c0f611c33013c3675355c0df175dd3b3f59aa75d7e277ad5861a7df46b03a84e96914817a1b682ea8d1d2841a20f459694a4419bbc796d357f4a4ab15a3b3f71d48c6c850cf716b6b5c810c3cd21f0d35c4a9890c5479dfd57f2e69face7201f0df81d6e5eba4f72aa6c0af57b729247cb8544cdc1e1d9619023fe8eadda5311c03b8bd2c2c830a7324ad490903c257c64bd9c9e5c2534205c4de701f023c3e2e0870012d0326cd52691089b1b470526128a860be8ed3de5a07b44bd0ee559d043ab8afbb6fd23cb9840130f95ed69e60536346a99954fb57c9dbf631dfe14aef3fcb5189fb015b64a5004f600d7ca5f5dded07b0bf29904b16af86f408bb2618754f7229a26563c892722580b70a185eb2d28fb2ada3983e334788688f49146b7d94fbbee93a789dcc277c3250f098435c4ac3ad60032b7812f769b367dddab9f83a5b26007b0eace6462d921fca3302a)

interpreter = Interpreter(nonce_client, nonce_server, enc_premaster, d, n)

msg = [
    (1, "738dd237531e694c06f147c41cbc7686a8fa8e79527fab456420ae03222b3e6cb43efba082174b6f31c82ea18dc83f49"),
    (0, "347df20d3450895a539d165a407074875b24976926297c343a0f3b6e9e0a85b193079a7bcebc1785dc9ed71f6fc8d30e"),
    (1, "253a269b0f8c1fa61760c935b1d5ff73e832ef37300b5066f6b47908ed7db338976d2cbe563edf3db8baf6020c810b911c52a3d7a55d26daccaff16ff14359c8"),
    (0, "35ad32db8d12084d27324c0d0eb4df54b2455a6624b25a92d99fbb89b9eec21d7fa46481c04415d33f493cfbe190bcee700ea25cc80cf9b362e7159ee553655e"), 
    (1, "a6f8cc8fbbe447d149acd326621ff86a9483306f1265a2db3c6ed16e448999b6d3092a52725765e7257a3de5c560d179"),
    (0, "2741a31ae73cc7f0a2b889302711786e69e66fd5a529496e03af68f35f020e9857ca13449332b61f0f00badc0dbd91965a7b036e15b8d0761ea950272abda41f7aba6d56f27fad36ca8635823988d7508267414be5fd716db077473405c29a78bce6a7106ed7e9eacfec398b5183261e") 
]

# for (f, m) in msg:
#     m = bytes.fromhex(m)
#     if f == 0:
#         print(interpreter.decrypt_server(m))
#     else:
#         print(interpreter.decrypt_client(m))

# b'Alice410\n\x8e\xeb\x0en8\x0ct\x05\xafU\xbf+\xa8*\xd2M\x04\xeb\xa2Z\x02\x02\x02'
# b'password: \x98bc>\xd6]\xe8\xa2\xe7(B5ia\xfd\x9f\x8fP[g\x01\x01'
# b'catsarecute\nI\xbe\xa0\xd8z\x06b\xd1\xe2*\x83\xeej\x02\xab\x17\\+\x86\xbf\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
# b'Enter your command:\n\x07<\xf3\xb4\xdf\x9c\x9d1v}!\xff-\xee\xa2\x0b\x9e\x96\xa9\xff\x07\x07\x07\x07\x07\x07\x07\x07'
# b'Alohomora!\n\x7f\xa3\x86\x9blm\xfayyHj\xdc\xbd\x9a\xe6-\xa4\x80\x12G\x00'
# b'FLAG{this is not real the flag, connect the server to get the flag!}\nBz\xe4\xae\x81\xbdc\x9ch\x96\x01\xbe\x82\xbf\xaa\x83\xacPI\xae\x06\x06\x06\x06\x06\x06\x06'

### session 4 ###

nonce_client = bytes.fromhex("10e3537daf03fdcc3392361986937fb9306d5425b34a61acf70ecacaf05490c3")
nonce_server = bytes.fromhex("e5624ac894c1133a675a7e57bb1dca798686034db8f8c28a444f574e47524401")
enc_premaster = int(0x018f3485b6b31fc2953321f12f4bfeb172a7da2e3cdd4b7605b03ccf6c141dabc13449d2c16b4cebc1b779bf826184343ec3d4ac223c30cc9f2afb397d288abb7be4d27a15e447136c2766cf96b5a37c1463573576486bd2a6975e37483a1ea2df91a0fcc23efea159cc2df35c3e7c7d86db4db7a609f31c378e095955fc737e244161b546ab99319804473a1b46aab5517a6b84f0fe0849168c63397f6bfb84b8b742cbc4a842f578aa17ce2d3494873f2754872309d0dd1b0a6bca0bbe900a5d5643081b3db82884da8cee09a05f44672a7ebde4002be2ecb356f46c1fab2f7dd493d11d9741130e349a53d542189bdce66fd498efe45dcb8dd4f8bdc414d7e0e1ce086e6aa255416d7c264e1e58d08a6f7e8f29b35d61968c501b52c235a0fafade1502671488595307a3ca78af320cfeb53f7716b3157bc39ef3daaf2418a392c8e118f961320eab29bb47e301c08d86157db3216b64a9960fc417551858e9805676b61daadd6ba4dc73fba0758e45be21b1cd80c9c047517cf1f195c6228c7f68db775f599817c5d72052b57d0a8ab68d39a12a1ca2251fcc31ddda5286e453c91b7b21c17fc2e2fd87ebb16462bb080719fb92f53faa92bd3d4377044313b0ec1ede28260f000d9358f99bc6d6199c18cdfb21b26369dc304ebc0ebb7ec5f3ffa18a0542c3a9f8c0e1229af6d6eb0c957127fcde38f7dceea3422833eb)

interpreter = Interpreter(nonce_client, nonce_server, enc_premaster, d, n)

msg = [
    (0, "76c2d9ac430ebc34390dce82af3b283aa8dcb7d9bbd9184c091a1d75270b97510ff40c9de42ac401ca576072ea2aeff70a2c3934a55796192584ecbab6f2f6bf"),
        (0, "c1da0b2dd50d9e123c6a667c2cd244a64b11c2eaf3be29266a414636517e7f7d66e1aac568934f89b79e363a93a2e8d4a3fd25665364c22cebc32ac29c39674e"),
        (0, "22e33283955ce7d594f3eadb35d9cff2876230ae04338ed1fdfac68aa5eda1df68f81e03b3d2580750cadadef993d463ddedd08a7ab720ecd879a72b25a97077"),
        (0, "0172cf9cbd49611d07b1b18a432466e6a48c6ec20cf7eeec79ed3db45347d362265aef6ad63e6ffaa1d970a56558c5ab"),
        (1, "5cf9d35b51ecbf2342637d295f6b1f707e2229c39d906e505640c09237981d471856349c44e60633f67f61e5a7dea994"),
        (0, "f53a717db2d09b567c76b25baca3fe2b9040b61b000cd6f617853299ad247ac8f2f1f0100c3601a0bc73399b4735f1c3"),
        (1, "a58a0740a2a5cac6a4c17d29ef6bd7297c20e435650092cb7e3b42618579a77d1864d8d7cfc123920e4055f3ed0d8ca00bb0ed06e631399fc1290b433692ba5f"),
        (0, "fcda3e537597e4e034482fda53f238a3d0f6f04ed616a18b19c3f7ad518e97ad592e010f7a8427debfd0fd4ebb332712534e5e0fb56f5cee54e1043b7b982442"),
        (1, "d14f5bf6f495c299a69832ccd7dc3b20431228ea0d21a98c715725874a2dc23a732e970f9597483c7b3ad75dcb6a14ec10868612515be20834c9e006d1833d36"),
        # root RSA private key 
        (0, "a439578d9322dd4d280b34bd71810afb4860e2fba305dd49256f2a3ca50ad4323975a6d5f6fbdc08d06206e3c36ebd153816c0d87f41866a520eee8f35838e2e2907e3daf444944d9096953473cfd92a42687a789592916e3d6ddc600d2daf91c80ebf9fd706c79d736b91d82a82d3e75f7b8354d35f02ab227ef1a3346d2405f088cc58096a00cd7780142325b712dc3d3a9b0a2eb73b1c3d64636253be142d2c682e870e956206212caecb3ea8f6b06f5d5a833bf0a22d36f310f3f6fce662afc8b668af39ae4366af3687be3d26404b554cb809c09db3ae917af505a8304b18f6974b9cea3b2e9229cef386b5d3cc30a294391690c580af8022cef761a4cc9cac0d797f75aef2aabf761d8759d0fc7c2bdafbacead37f5e293a967c0970f927dc2bd179f2d2c2b0ba7df38030c57de5150ab9102daa0aaba5b90085e2ad3780fad98ded0fe6e824df5342b382fce193f205c8fe2df0037713fa6c82ff06b48695a32934ce708ea798496248c775dc83de1f57f1162b9fd7b2d57a4243aca1c91280b7901b81606d644d763f7f027e43dd2a08cc55144ea137a5407e2b826a48f572a2f4621f7c56de8f431e0d3fc02dd039631f8cd5cc4402d232e4a850df2f1ab8954c68e2a93e27a9598d76569cc18c531fa105df04c5c1e27923102c6a3beaa36d3d5da16be09c15749f0914ff1f37daecd84856b4704e983d11ff77892aae6f3f5e4af85b2db485fa624ef3cb2665ca493342a7d9ef2b68e5d24ca95f232f6de703e1ef9c8d029ba52aa955e7a0c7a98e8e77714030af663b67b34463df865d23136252d40385f073a95c03f4e03eade4a43eb6c079b5559d72d7499fbd1641d1238dbf308018ad02a7697c2494a73399c7d7dbe1007936c4f45a25f7bc5346a141e2a69ecd8dd5b3c07454987aa55a307375c49288d833b9c050ff1ce9c54f15dc9e79c7f7068f98dfc0827f167704d6dbb48e1b88731078c80519a8f760c7fd270d2a9b9a5d806ac3cece9301038a80241c755419a9a59a3e2d6486d07918d0e1186390e1ced7e4b33d2580b18493148983fbee2dc7013f13469210668e6690efcefe7e627dfa782244660afb3e821cf8ff90d80f1d59f173b70786376feccff3d26cb241837f14be8deedad10567e895841784c05ce9cf05f7e6fd660963ace86396742ffa2617e864f3c5247343d7ccbd19578a69fed16dfd4390a744d36c6723985bd716dc53278cd092d08cb334aca2e97e873632ab30a72dba39a59223793d61b7209deeba95ccb49f4201d976cc9f1f35c01b48240d0cce9f43b54bbf109565744d3b28ba9a0ed1600161c62017591305e0571a7ad8543f65d4cdd6f8b3b2c86133b81899f5be5e564beacebb4ea44fcb2fa9b92832cb1449b272ad38d202d8dc27b72d9cb365357f30fcdd7e7eae5d31e98bff5fb15807227aa7742f72ad5d0001e680dd60d3d017fa27a1aad28d08c6e4d3a450f912e056570996fa3db35f5064199414931c3b05c5dc8585f2b14fcce06c37c9bb44380660956b48e38aa99a2b4390376648ed5a7e8e1ceaf7ed588a6e9002cb067bdaf5226b0351fa8fcc44bb5035dfa22acd87a38464ca3b0da561e68d8344db400dee62e29d594e18a300f69391a8214242b10b11c1226588973c8abdb3350ecc38201ae92d3a5b642196033fb6052f86f09faec3ea01bbea7c605d4453d85b3c131acf8389abfe8bc9dd245795ff89a8f03cb2f45be5891de2c328dd14de870a076510bc86bce257f05003f966dd7be4fab07a1543fed8248b6571a261d7755c3fdc463456ec61f8295c2592dd2083ec54bca4c24e28d9f1f4e82787687768bcf7767a9ed121a4d1105a7eca97aef2e2ee734d96e5783b79e1fda5678817385d262cc095461f9e7e210724df9b3c1688c5eb0854d8b826fa9e6afd6e52b7217774ba40bf6fee4566abeefdd4f80cdaf80d8ef7f67ea7abe1d3b26c905fa6d0c187c959f6fb79070c5bd8cc55a4cb8f73e73100ad73b7ced0ff0cc60e09a50975f8f2635fed49464ee7289ccbee7aa70b24b8f0883c2542fea79b595f0dc3b86a67459e6e1548445e23c1a19237e98e4d16020426899db860cadfe5404acbad1e1407a9bd5213d6a33be04031b2dd321ca28abac56b3846a6d23f7bcaa8de5928489dce1449e4b447c0fe37b920439e7aaa12b3042de9b77fb2ec14504c4d31ecf5ac7b3d090c8b26225d5c9404b4acedaa23c8e723c1037b716667238bd31af9cbc79e74185eb0d566d503f9f3325119bb4f7fcf1b7c68afef85f6c076040e7ebf2180d7d1a8dfce11b8a5347071f01e6ed7cb0d559cbd6ed00b64b6d8e6c6e39319924ce75acf5d65d4d52a97f2bf726db2ec2dc141f168eee7639b48a613552a5d742f09d920ff1d9adbb6b7089966c4db643c487a29fc9fd80153ad04090f210aa011caa7df440055c3c0c62e5de8b9f4f38e67560c553d2aca347a66ea13e3d0390dc3cec9dcfea73da6cdd20c54f70caa4f15653393332ddebda264e2d2b4f952525726c85595511fe1cf224b886cadb9c92ffca1a3b7adc11af872f6c61fbc82f998adca42a3d69c8b71ff52badcab357f9da583d08f242655683dc472189515d7a931f3fb511cdc6ed51984e44518ab3c4b514646f914cd345d808755421296fe9a34d63538acce1dde73d3d746cdb7b744d94a5844b829ba1360109d632bb6be4d7347240838601117e2d522477a8172d24f3f6b1f501f0c8bd902da4bcd29464175c54c5de7032a6bba7ad3de3a5112cc082ce395f63d7d0f0f259e529c3a47e62d63674cb77cf90b1f6a64e001d79436165c803888ad4fb399466af6ca2ac26c0a1d30579b2ae1d1c473022f2965eaba1d6606080696c89ba9a01c074463b17df65747fc0ac342798ffd36b3b68ed1352347a6a7300638758340367babc4f5fcb675d1d18b6bb7cb4c27730e213784bcb86d5e1004657c8ba5a8369242de0cf9abdf04f1d9ef7ca2728c6a06fa23a060911d428893d6d481cc75284037c421f61939ca430f86b4d90b5286aadec4f815e0a78569d432f73bcb6da61d12794058bbe60112931616de96990c302bf4e0519a46c0fdcf1d726be33592b2dcefffe5c43566d7a82bbe3724f6a3e8949d7c79a771a6c8af41a1eb9057a1e3eeaff17acd63c6debc4b0c922b73895c8f3bc9e4a5ded86d8039b4bfb8eb0d52e7bf4fe65999cb21bde323bd8564156617f2d23c8e85ed8bfb9ef0b6bcfb71ff7f4a5e6a14df0ccbb40630b0d9f694ef37bfd0eae895a05b9b6faa00e4b534ed190bea41e53cd439c6183ff960b0e97f5099ce3a7938d5b73baa2c8f31e698b59bdeb3b55c49206a25176fe90b80afbd3647421de867d0a3d567206b1a2da4b16b7f9adcd0fda10bb31a38cb2270ee5f6cafef24ddd2f7ee7505bea94f4c23279156462b4d8b2ec87b9ca564e58da16035bdb1007f6ffe64b99b8cc2d1f1599db45d395f63aed8369206e9361ada6c1b78f512c70d781a4f1999a8f510bbbb3a7b533b351364a890bda53a17f6364d79881ccad4f2a17a56882cadb839ded4d24da9854d9a2dee77ac4c87c3563aa7cddc84f6b7d487d5ee0846cad2e6f986275da865e44902adad040950db74183c48a5089d032b8e6b7dc36f77d87dd24c31b42354b69b7f6e82416f302ca7e11c6e766bd5689e84c7c8a03a8fc44f6130fd942c23bfa2ccf540cb6159dfe21310d8b7b96392da28cbe937716bba5bba14dacb0e8fd7633026c0808139d8230ad922bd32246d6c5df7a12f3724c545904446615426405926827c11b7d48b9b1fdfcdc7384adec2ab906f16d1e72b9c9ab442e101bf20d08bb7bae02097534d27c2d2c23c635ad6afb35529ab66c0266400d56464b2984838a213a27f0254970889dd524b172885439c1d399fe1b1e4785f7b72eea0cc499d6876a60d87c5e1787853bb04a1f9250313f5b9fe640d8554a8ef2495a7eb5c5a02f4907ef6a6975723a9788934d4306c713bb6910aa94e4847ea8f7ecfbcab317189c29e4d1b00ea8c3076289b7dbebc3952a77618c6980526b8d0b5f10f6b2dd4fe9a9bef27276c2076f819497fce54eeece03eb2e5a9c3c80063878605be39d87a7763a1204c64f5f651eb3afddca9830ca452e0a09761dba577ee33ffb1b6ab8a207578d1839bd126a6bef6138cf641d420072d5863dd8117a35d5b4849f0141aafade155991c21a8cbad32c516fc125662ae10b8454a9f9ac2018948d72a6bb4f36c48095012a86babcf0a360ae84e1a905f092db372c3b0f9294cf2e48938d7870846a4eae40200c31d6095132c448ebe78845fc75acecf26a5b97d56a69559cb807bbb3b06f52f5ea8afe65b79b5f326601b7c95c6c830677f66ba53a5d20882e454242f564101346ca9ce9007139aa884ce804e620eeb791afc03420018e59810dc8d9f85108181ac3af59384e1113784ed09c04952262d1c120e2db50ffc9a4edf263a63930bd172f90a8e19b9325f691d299835d22fceee4fae446b179dd2fa64fff201ea6415ae50c38d4a60d2a73a38d0ae3c3f4a3838306570dd0a003d810fcf405a89a436be8180d76b3a32e973f474c71d871d7b5f684710d864584f23486627fc567dce"),]

# for (f, m) in msg:
#     m = bytes.fromhex(m)
#     if f == 0:
#         print(interpreter.decrypt_server(m))
#     else:
#         print(interpreter.decrypt_client(m))

# b'login as: \x13\x92\xe8I\x87\x05\xbd\xbe\x89\x88k\xa6\xa6\xd8\x94\xa390\xb8\x83\x01\x01'
# b'Alice410\n\xe9\x88!\xe5\xed72\xc1(C\xbaF\xe7n\x01T\x10\xaav_\x02\x02\x02'
# b'password: \x89/:\xe4\x84 \x19\xe6[R\xbc\xb6\xb923a\xdeg\x1f_\x01\x01'
# b'catsarecute\n\x1cX\xca\xb4\xda\xa5\x8a\x19<\x16\x90&\x85lOD&\xdf\x96\x1d\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
# b'Enter your command:\n=\xfb\xbd\xc3D\x8f\x0cO\xed\xec\xc4\xfa\xf8~\xbc\xd5\x89\x92<\xf6\x07\x07\x07\x07\x07\x07\x07\x07'
# b'Get rootCA.key\n\xba\x8b\x16p\x0b\xc6f\xc0\xcaK\x91\xb9h\xbe\xdd\xa1#\x177\xcb\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
# b'-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n

#####################
### Write RSA key ###
#####################

RSA_KEY = interpreter.decrypt_server(bytes.fromhex(msg[-1][1]))[:-21]
f = open("ssl/rootCA.key", "wb")
f.write(RSA_KEY)
f.close()

#############################################
### create domain key, domain certificate ###
#############################################

# https://www.baeldung.com/openssl-self-signed-cert

### openssl client ###

### ssl/rootCA.crt ###
#  openssl s_client -showcerts -connect cns.csie.org:12345
#       - copy the rootCA certificate to ssl/rootCA.crt

### ssl/domain.key ###
# openssl genrsa -out ssl/domain.key 2048

### ssl/domain.ext ###
### should be the following content ###
# authorityKeyIdentifier=keyid,issuer
# basicConstraints=CA:FALSE
# subjectAltName = @alt_names
# [alt_names]
# DNS.1 = domain

### ssl/domain.crt ###
# openssl req -key ssl/domain.key -new -out ssl/domain.csr
#   - Enter: TW, Taiwan, Taipei, NTU CNS, student, cns.csie.org, alice@csie.ntu.edu.tw
# openssl x509 -req -CA ssl/rootCA.crt -CAkey ssl/rootCA.key -in ssl/domain.csr -out ssl/domain.crt -days 365 -CAcreateserial -extfile ssl/domain.ext

#########################
### connect to server ###
#########################

# https://gist.github.com/shanemhansen/3853468

hostname = 'cns.csie.org'
port = 12345

context = SSL.Context(SSL.SSLv23_METHOD)
context.use_certificate_chain_file("ssl/domain.crt")
context.use_privatekey_file("ssl/domain.key")

sock = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
sock.connect((hostname, port))

print(sock.recv(1024))
print(sock.recv(1024))
print(sock.recv(1024))
print(sock.recv(1024)) # login
sock.sendall(b"Alice410\n")
print(sock.recv(1024)) # password
sock.sendall(b"catsarecute\n")
print(sock.recv(1024)) # Enter your command
sock.sendall(b"Alohomora!\n")
print(sock.recv(1024))